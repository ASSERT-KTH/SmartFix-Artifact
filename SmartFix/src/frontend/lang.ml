open Vocab
open Options

module Node = struct
  type t = ENTRY | EXIT | Node of int

  let equal n1 n2 =
    match n1, n2 with
    | ENTRY, ENTRY -> true
    | EXIT, EXIT -> true
    | Node i1, Node i2 -> i1 = i2
    | _, _ -> false

  let hash = Hashtbl.hash

  let compare = Stdlib.compare

  let entry = ENTRY
  let exit = EXIT

  let nid = ref 0

  let make () = nid := !nid + 1; Node !nid

  let to_string : t -> string
  = fun n ->
    match n with
    | ENTRY -> "ENTRY"
    | EXIT -> "EXIT"
    | Node i -> string_of_int i
end

type node = Node.t

module G = Graph.Persistent.Digraph.Concrete (Node)

let trans_node = Node.Node 0
let extern_node = Node.Node (-1)

(********************)
(********************)
(***** language *****)
(********************)
(********************)

type pgm = contract list

and contract = id * state_var_decl list * structure list * enum list * func list * cinfo

and state_var_decl = id * exp option * vinfo

and structure = id * var_decl list
and var_decl = id * vinfo

and enum = id * enum_mem list
and enum_mem = id

and func = id * param list * ret_param list * stmt * finfo
and param = id * vinfo
and ret_param = id * vinfo

and fsig = id * typ list
and fkey = id * id * typ list
and func_decl = id * var list * var list 
and visibility = Public | Internal | External | Private

and var = id * typ

and vultyp = string

and stmt =
  | Assign of lv * exp * loc
  | Decl of lv
  | Seq of stmt * stmt
  | Call of lv option * exp * exp list *
            exp option * exp option * (* ether, gas *)
            loc
  | Skip
  | If of exp * stmt * stmt * ifinfo
  | While of exp * stmt
  | Break
  | Continue
  | Return of exp option * loc
  | Throw
  | Assume of exp * loc
  | Assert of exp * vultyp * loc (* used to check safety conditions *)
  | Assembly of (id * int) list * loc
  | PlaceHolder (* _ *)
  | Unchecked of stmt list * loc (* unchecked block *)

and exp =
  | Int of BatBig_int.t
  | Real of float 
  | Str of string
  | Lv of lv
  | Cast of typ * exp
  | BinOp of bop * exp * exp * einfo
  | UnOp of uop * exp * typ
  | True | False
  | ETypeName of elem_typ (* may be second arguments of abi.decode functions *)
  | IndexRangeAccess of lv * exp option * exp option * einfo (* base, start op, end op *)
  | TypeInfo of typ * id * einfo (* type(T).fieldname *)

  (* exists only in the interim process *)
  | IncTemp of exp * bool * loc (* true if prefix, false if postfix *)
  | DecTemp of exp * bool * loc
  | CallTemp of exp * exp list *
                exp option * exp option * (* ether, gas *)
                einfo
  | CondTemp of exp * exp * exp * typ * loc
  | AssignTemp of lv * exp * loc

and bop =
  | Add | Sub | Mul | Div | Mod | Exponent
  | GEq | Gt | LEq | Lt | LAnd | LOr | Eq | NEq
  | ShiftL | ShiftR | BXor | BAnd | BOr

and uop =
  | Pos | Neg | LNot | BNot

and lv =
  | Var of (id * vinfo)
  | MemberAccess of exp * id * vinfo * typ (* exp.id / vinfo is for id *)
  | IndexAccess of exp * exp option * typ (* exp[exp?] *)
  | Tuple of exp option list * typ (* [a, b, c, d, ] *)

and id = string
and line = int

and loc = {
  line : line;
  finish_line : line;
  offset : int; (* in byte *)
  len : int     (* in byte *)
}

and cinfo = {
  numid : int;
  inherit_order : int list;
  lib_typ_lst : (id * typ) list; (* a list of pairs of (lib name, aliased type). Orders do not matter. *)
  ckind : string
}

and vinfo = {
  vloc : loc;
  is_gvar : bool;
  vtyp : typ;
  vvis : visibility;
  vid : int;
  refid : int; (* referenced declartion. valid only for non-function variables *)
  vscope : int; (* belonging contract numid (global) or func numid (local) *)
  storage : string;
  flag : bool; (* true if the information is propagated *)
  org : exp option (* original expression (source code) before renamed or replaced *)
}

and einfo = {
  eloc : loc; 
  etyp : typ;
  eid : int
}

and ifinfo = {
  if_loc : loc;
  if_tloc : loc;
  if_floc : loc option; (* None means no 'else' block exists in original code *)
}

and mod_call = id * exp list * loc
and state_mutability = Payable | NonPayable | View | Pure

and finfo = {
  is_constructor : bool;
  is_payable : bool;
  is_modifier : bool;
  mod_list : mod_call list;
  mod_list2 : mod_call list; (* constructor modifier invocations *)
  param_loc : loc; (* line of '(' and ')' *)
  ret_param_loc : loc; (* location where ret params are delclared *)
  fvis : visibility;
  mutability: state_mutability;
  fid : int;
  floc : loc;       (* start line: 'function' keyword, endling line: '}' *)
  scope : int;      (* belonging contract numid *)
  scope_s : id;     (* belonging contract name *)
  org_scope_s : id; (* original contract name in which functions are initially defined *)
  cfg : cfg
}

and cfg = {
  graph          : G.t;
  outpreds_of_lh : node BatSet.t; (* preds of loop headers outside of loops *)
  lh_set         : node BatSet.t; (* loop header set *)
  lx_set         : node BatSet.t; (* loop exit set *)
  continue_set   : node BatSet.t;
  break_set      : node BatSet.t;
  extern_set     : node BatSet.t; (* nodes in external contexts. only valid in exploit mode *)
  basic_paths    : node list BatSet.t;
  stmt_map       : (node, stmt) BatMap.t;
  signature      : fkey
}

and typ =
  | ConstInt
  | ConstString
  | ConstReal
  | EType of elem_typ
  | Struct of id list
  | Mapping of elem_typ * typ
  | Mapping2 of typ * typ
  | Array of typ * int option (* type, (size)? *)
  | TupleType of typ list
  | FuncType of typ list * typ list
  | Void (* dummy type *)

and elem_typ =
  | Contract of id
  | Enum of id
  | Address
  | AddressPayable
  | Bool
  | String
  | UInt of int
  | SInt of int
  | Bytes of int (* fixed-size byte arrays *)
  | DBytes (* dynamically-sized byte arrays *)
  (* | Fixed | UFixed *)

let dummy_loc = { line = -1; finish_line = -1; offset = -1; len = -1 }

let mk_loc ?(line=(-1)) ?(finish_line=(-1)) ?(offset=(-1)) ?(len=(-1)) () =
  let finish_line = max line finish_line in
  { line = line; finish_line = finish_line; offset = offset; len = len }

let dummy_vinfo =
  {vloc = dummy_loc; is_gvar = false; vtyp = Void; vvis = Private; vid = -1; refid = -1; vscope = 1; storage = ""; flag = false; org = None}

let mk_vinfo ?(loc=dummy_loc) ?(typ=Void) ?(org=None) () =
  {vloc = loc; is_gvar = false; vtyp = typ; vvis = Private; vid = -1; refid = -1; vscope = -1; storage = ""; flag = false; org = org}

let dummy_ifinfo = { if_loc = dummy_loc; if_tloc = dummy_loc; if_floc = Some dummy_loc }

let empty_cfg = {
  graph           = G.empty;
  outpreds_of_lh  = BatSet.empty;
  lh_set          = BatSet.empty;
  lx_set          = BatSet.empty;
  continue_set    = BatSet.empty;
  break_set       = BatSet.empty;
  extern_set      = BatSet.empty;
  basic_paths     = BatSet.empty;
  stmt_map        = BatMap.empty;
  signature       = ("Dummy","Dummy",[])
}

let find_stmt : node -> cfg -> stmt
= fun n g -> 
  try if n = Node.ENTRY || n = Node.EXIT then Skip
      else BatMap.find n g.stmt_map
  with Not_found -> failwith ("No stmt found in the given node " ^ Node.to_string n)

let nodes_of : cfg -> node list
= fun g -> G.fold_vertex (fun x acc -> x::acc) g.graph []

let has_loop : cfg -> bool
= fun g -> not (BatSet.is_empty g.lh_set) (* inspect whether loop headers exist *)

let find_contract_id : pgm -> id -> contract
= fun contracts id ->
  List.find (fun (cid,_,_,_,_,_) -> BatString.equal cid id) contracts

let find_contract_nid : pgm -> int -> contract
= fun contracts nid ->
  List.find (fun (_,_,_,_,_,cinfo) -> nid = cinfo.numid) contracts

let get_main_contract : pgm -> contract
= fun pgm ->
  if BatString.equal !main_contract "" then BatList.last pgm
  else
    try find_contract_id pgm !main_contract
    with _ -> failwith ("main contract name mathcing failed : " ^ "\'"^ !main_contract ^ "\'")

let get_cname : contract -> id
= fun (cid,_,_,_,_,_) -> cid

let get_decls : contract -> state_var_decl list
= fun (_,decls,_,_,_,_) -> decls

let get_structs : contract -> structure list
= fun (_,_,structs,_,_,_) -> structs

let get_enums : contract -> enum list
= fun (_,_,_,enums,_,_) -> enums

let get_all_structs : pgm -> structure list
= fun pgm ->
  List.fold_left (fun acc c -> (get_structs c) @ acc) [] pgm 

let get_cnames : pgm -> id list
= fun pgm -> List.map get_cname pgm

let get_gvars_c : contract -> var list
= fun c ->
  let decls = get_decls c in
  List.map (fun (x,_,vinfo) -> (x,vinfo.vtyp)) decls

let get_gvars : pgm -> var list
= fun p ->
  let main = get_main_contract p in
  let decls = get_decls main in
  List.map (fun (x,_,vinfo) -> (x,vinfo.vtyp)) decls

let get_cinfo : contract -> cinfo
= fun (_,_,_,_,_,cinfo) -> cinfo

let get_libnames : pgm -> id list
= fun pgm ->
  let libs = List.filter (fun c -> BatString.equal (get_cinfo c).ckind "library") pgm in
  List.map get_cname libs

let get_numid : contract -> int
= fun (_,_,_,_,_,cinfo) -> cinfo.numid

let get_fname : func -> id (* detach this function *)
= fun (fname,_,_,_,_) -> fname

let is_payable : func -> bool
= fun (_,_,_,_,finfo) -> finfo.is_payable

let get_funcs : contract -> func list
= fun (_,_,_,_,funcs,_) -> funcs

let get_fnames : contract -> id list
= fun (_,_,_,_,funcs,_) -> List.map get_fname funcs 

let get_cnstr : contract -> func
= fun (_,_,_,_,funcs,_) ->
  let lst = List.filter (fun (_,_,_,_,finfo) -> finfo.is_constructor) funcs in
  let _ = assert (List.length lst = 1) in
  List.hd lst

let gen_func ~fname ~params ~ret_params ~stmt ~finfo 
= (fname,params,ret_params,stmt,finfo) 

let update_cinfo : cinfo -> contract -> contract
= fun cinfo (cid,decls,structs,enums,funcs,_) -> (cid,decls,structs,enums,funcs,cinfo)

let update_enums : enum list -> contract -> contract
= fun enums (cid,decls,structs,_,funcs,cinfo) -> (cid,decls,structs,enums,funcs,cinfo)

let update_structs : structure list -> contract -> contract
= fun structs (cid,decls,_,enums,funcs,cinfo) -> (cid,decls,structs,enums,funcs,cinfo)

let update_funcs : func list -> contract -> contract
= fun funcs (cid,decls,structs,enums,_,cinfo) -> (cid,decls,structs,enums,funcs,cinfo)

(* include itself *)
let get_inherit_order : contract -> int list
= fun (_,_,_,_,_,cinfo) -> cinfo.inherit_order (* itself => parents *)

let is_library_kind : contract -> bool
= fun c -> BatString.equal (get_cinfo c).ckind "library"

let is_interface_kind : contract -> bool
= fun c -> BatString.equal (get_cinfo c).ckind "interface"

let is_contract_kind : contract -> bool
= fun c -> BatString.equal (get_cinfo c).ckind "contract"

let get_finfo : func -> finfo
= fun (_,_,_,_,finfo) -> finfo

let get_mod_calls : func -> mod_call list
= fun (_,_,_,_,finfo) -> finfo.mod_list

let get_vis : func -> visibility
= fun f -> (get_finfo f).fvis

let is_public = function 
  | Public -> true | _ -> false

let is_external = function
  | External -> true | _ -> false

let is_internal = function 
  | Internal -> true | _ -> false

let is_private = function
  | Private -> true | _ -> false

let is_public_func : func -> bool
= fun f -> is_public (get_vis f)

let is_external_func : func -> bool
= fun f -> is_external (get_vis f)

let is_internal_func : func -> bool
= fun f -> is_internal (get_vis f)

let is_private_func : func -> bool
= fun f -> is_private (get_vis f)

let get_mutability : func -> state_mutability
= fun f -> (get_finfo f).mutability

let is_view_pure_f : func -> bool
= fun f ->
  let mut = get_mutability f in
  mut = View || mut = Pure

let update_finfo : finfo -> func -> func
= fun finfo (id,params,ret_params,stmt,_) -> (id,params,ret_params,stmt,finfo)

let is_constructor : func -> bool
= fun f -> (get_finfo f).is_constructor

let is_modifier : func -> bool
= fun f -> (get_finfo f).is_modifier

let get_body : func -> stmt
= fun (_,_,_,stmt,_) -> stmt

let update_body : stmt -> func -> func
= fun stmt' (id,params,rets,_,finfo) -> (id, params, rets, stmt', finfo)

let update_fname : id -> func -> func
= fun id' (_,params,rets,stmt,finfo) -> (id', params, rets, stmt, finfo)

let modify_contract : contract -> pgm -> pgm
= fun c p ->
  let cname = get_cname c in 
  List.map (fun c' -> 
    if BatString.equal cname (get_cname c') then c 
    else c'
  ) p

let get_cfg : func -> cfg
= fun func -> (get_finfo func).cfg

let update_cfg : func -> cfg -> func
= fun f g ->
  let finfo = get_finfo f in
  update_finfo {finfo with cfg = g} f

let is_outer_pred_of_lh : node -> cfg -> bool
= fun n g -> BatSet.mem n g.outpreds_of_lh

let is_loophead : node -> cfg -> bool
= fun n g -> BatSet.mem n g.lh_set

let is_loopexit : node -> cfg -> bool
= fun n g -> BatSet.mem n g.lx_set

let is_continue_node : node -> cfg -> bool
= fun n g -> BatSet.mem n g.continue_set

let is_break_node : node -> cfg -> bool
= fun n g -> BatSet.mem n g.break_set

let is_callnode : node -> cfg -> bool
= fun n g ->
  match find_stmt n g with
  | Call _ -> true
  | _ -> false

let extcall = Call (None, Lv (Var ("@extern", dummy_vinfo)), [], None, None, dummy_loc)

let is_external_call : stmt -> bool
= fun stmt ->
  match stmt with
  | Call (None, Lv (Var ("@extern", _)), args, None, None, _) -> true
  | _ -> false

let is_extern_log_stmt : stmt -> bool
= fun stmt ->
  match stmt with
  | Call (_,Lv (Var ("@extern_log",_)),exps,_,_,_) -> true
  | _ -> false

let is_extern_log_node : node -> cfg -> bool
= fun n g ->
  match find_stmt n g with
  | Call (_,Lv (Var ("@extern_log",_)),exps,_,_,_) -> true
  | _ -> false

let get_fname_extern_log_stmt : stmt -> string
= fun stmt ->
  match stmt with
  | Call (_,Lv (Var ("@extern_log",_)),Lv (Var (fname,_))::args,_,_,_) -> fname
  | _ -> assert false

let get_fname_extern_log_node : node -> cfg -> string
= fun n g ->
  match find_stmt n g with
  | Call (_,Lv (Var ("@extern_log",_)),Lv (Var (fname,_))::args,_,_,_) -> fname
  | _ -> assert false

let is_skip_node : node -> cfg -> bool
= fun n g ->
  match find_stmt n g with
  | Skip -> true
  | _ -> false

let is_exception_node : node -> cfg -> bool
= fun n g ->
  match find_stmt n g with
  | Throw -> true
  | Call (lvop, Lv (Var ("revert",_)),args,_,_,_) -> true
  | _ -> false

let is_assign_node : node -> cfg -> bool
= fun n g ->
  match find_stmt n g with
  | Assign _ -> true
  | _ -> false

let is_entry : node -> bool
= fun n ->
  match n with
  | Node.ENTRY -> true
  | _ -> false

let is_exit : node -> bool
= fun n ->
  match n with
  | Node.EXIT -> true
  | _ -> false

let is_uintkind : typ -> bool
= fun t ->
  match t with
  | EType UInt _ -> true
  | _ -> false

let is_uint256 t =
  match t with
  | EType (UInt 256) -> true
  | _ -> false

let is_sintkind : typ -> bool
= fun t ->
  match t with
  | EType SInt _ -> true
  | _ -> false

let is_mapping : typ -> bool
= fun t ->
  match t with
  | Mapping _ -> true
  | _ -> false

let is_mapping2 : typ -> bool
= fun t ->
  match t with
  | Mapping2 _ -> true
  | _ -> false

let is_usual_mapping : typ -> bool
= fun t ->
  match t with
  | Mapping (Address, EType (UInt 256)) -> true
  | _ -> false

let is_usual_allowance : typ -> bool
= fun t ->
  match t with
  | Mapping (Address, Mapping (Address, EType (UInt 256))) -> true
  | _ -> false

let is_bool : typ -> bool
= fun t ->
  match t with
  | EType Bool -> true
  | _ -> false

let is_address : typ -> bool
= fun t ->
  match t with
  | EType Address -> true
  | _ -> false

let is_address_payable : typ -> bool
= fun t ->
  match t with
  | EType AddressPayable -> true
  | _ -> false

let is_address_kind : typ -> bool
= fun t -> is_address t || is_address_payable t

let is_array : typ -> bool
= fun t ->
  match t with
  | Array _ -> true
  | _ -> false

let is_static_array : typ -> bool
= fun t ->
  match t with
  | Array (_,Some _) -> true
  | _ -> false

let get_array_size : typ -> int option
= fun t ->
  match t with
  | Array (_,Some n) -> Some n
  | Array (_,None) -> None
  | _ -> raise (Failure "get_array_size")

let is_dynamic_array : typ -> bool
= fun t ->
  match t with
  | Array (_,None) -> true
  | _ -> false

let is_contract : typ -> bool
= fun t ->
  match t with
  | EType (Contract _) -> true
  | _ -> false

let is_struct : typ -> bool
= fun t ->
  match t with
  | Struct _ -> true
  | _ -> false

let is_enum : typ -> bool
= fun t ->
  match t with
  | EType (Enum _) -> true
  | _ -> false

let is_elem_typ : typ -> bool
= fun t ->
  match t with
  | EType _ -> true
  | _ -> false

let is_user_defined_typ : typ -> bool
= fun t ->
  match t with
  | EType (Enum _) | EType (Contract _) | Struct _ -> true
  | _ -> false

let is_dbytes : typ -> bool
= fun t ->
  match t with
  | EType DBytes -> true
  | _ -> false

let is_bytes : typ -> bool
= fun t ->
  match t with
  | EType (Bytes _) -> true
  | _ -> false

let is_bytekind : typ -> bool
= fun t -> is_dbytes t || is_bytes t

let is_const_int : typ -> bool
= fun t ->
  match t with
  | ConstInt -> true
  | _ -> false

let is_uintkind_or_constint : typ -> bool
= fun t -> is_uintkind t || is_const_int t

let is_const_string : typ -> bool
= fun t ->
  match t with
  | ConstString -> true
  | _ -> false

let is_string : typ -> bool
= fun t ->
  match t with
  | EType String -> true
  | _ -> false

let is_tuple : typ -> bool
= fun t ->
  match t with
  | TupleType _ -> true
  | _ -> false

let is_func_typ typ =
  match typ with FuncType _ -> true | _ -> false

let is_void : typ -> bool
= fun t ->
  match t with
  | Void -> true
  | _ -> false

let domain_typ : typ -> typ
= fun typ ->
  match typ with
  | Array _ -> EType (UInt 256) 
  | Mapping (et,_) -> EType et
  | Mapping2 (t,_) -> t
  | EType DBytes -> EType (UInt 256)
  | EType (Bytes _) -> EType (UInt 256)
  | _ -> failwith "domain_typ"

let range_typ : typ -> typ
= fun typ ->
  match typ with
  | Array (t,_) -> t
  | Mapping (_,t) -> t
  | Mapping2 (_,t) -> t
  | EType DBytes -> EType (Bytes 1)
  | EType (Bytes _) -> EType (Bytes 1)
  | _ -> failwith "range_typ"

let get_func_ret_typs : typ -> typ list
= fun typ ->
  match typ with
  | FuncType (_,rt) -> rt
  | _ -> failwith "get_func_ret_typs"

let tuple_elem_typs : typ -> typ list
= fun t ->
  match t with
  | TupleType lst -> lst
  | _ -> failwith "tuple_elem_typs"

let get_bytes_size : typ -> int
= fun t ->
  match t with
  | EType (Bytes n) -> n
  | _ -> failwith "get_bytes_size"

let exp_to_lv : exp -> lv
= fun exp ->
  match exp with
  | Lv lv -> lv
  | _ -> raise (Failure "exp_to_lv") 

let get_type_var : var -> typ
= fun var -> snd var

let get_type_var2 : id * vinfo -> typ
= fun (v,vinfo) -> vinfo.vtyp

let get_type_lv : lv -> typ
= fun lv ->
  match lv with
  | Var (_,vinfo) -> vinfo.vtyp
  | MemberAccess (_,_,_,typ) -> typ 
  | IndexAccess (_,_,typ) -> typ 
  | Tuple (_, typ) -> typ

let get_type_exp : exp -> typ
= fun exp ->
  match exp with
  | Int _ -> ConstInt
  | Real _ -> ConstReal
  | Str _ -> ConstString
  | Lv lv -> get_type_lv lv 
  | Cast (typ,_) -> typ
  | BinOp (_,_,_,einfo) -> einfo.etyp
  | UnOp (_,_,typ) -> typ
  | True | False -> EType Bool
  | ETypeName etyp -> EType etyp
  | IndexRangeAccess (_,_,_,einfo) -> einfo.etyp
  | TypeInfo (_,_,einfo) -> einfo.etyp
  | _ -> failwith "get_type_exp"

let get_type_array_elem : typ -> typ
= fun typ ->
  match typ with
  | Array (t,_) -> t
  | _ -> failwith "get_type_array_elem"

let get_int : exp -> int
= fun exp ->
  match exp with
  | Int bigint -> BatBig_int.to_int bigint
  | _ -> failwith "get_int"

let get_bigint : exp -> BatBig_int.t
= fun exp ->
  match exp with
  | Int bigint -> bigint
  | _ -> failwith "get_bigint"

let big_lt = BatBig_int.lt_big_int
let big_neg = BatBig_int.neg
let big_ge = BatBig_int.ge_big_int
let big_pow n1 n2 = BatBig_int.pow (BatBig_int.of_int n1) (BatBig_int.of_int n2)

(* 0 <= X < 2^n *)
let rec bit_unsigned_of_int : BatBig_int.t -> int -> int 
= fun n bit ->
  let _ = assert (bit <= 256) in
  if big_lt n (big_pow 2 bit) then bit (* meaning EType (UInt bit) *)
  else bit_unsigned_of_int n (bit+8)

(* -2^(n-1) <= X < 2^(n-1) *)
let rec bit_signed_of_int : BatBig_int.t -> int -> int
= fun n bit ->
  let _ = assert (bit <= 256) in
  if big_ge n (big_neg (big_pow 2 (bit-1))) && big_lt n (big_pow 2 (bit-1)) then bit (* meaning EType (SInt bit) *)
  else bit_signed_of_int n (bit+8)

let is_skip stmt =
  match stmt with Skip -> true | _ -> false

let get_fname (fname,_,_,_,_) = fname
let get_body (_,_,_,stmt,_) = stmt

let get_params (_,params,_,_,_) = params
let get_param_vars (_,params,_,_,_) = List.map (fun (v,vinfo)-> (v,vinfo.vtyp)) params
let get_param_types (_,params,_,_,_) = List.map (fun p -> (snd p).vtyp) params

let get_ret_params (_,_,ret_params,_,_) = ret_params
let get_ret_param_vars (_,_,ret_params,_,_) = List.map (fun (v,vinfo)-> (v,vinfo.vtyp)) ret_params
let get_ret_param_types (_,_,ret_params,_,_) = List.map (fun p -> (snd p).vtyp) ret_params


let get_fsig : func -> id * typ list
= fun f -> (get_fname f, get_param_types f)

let equal_sig : func -> func -> bool
= fun f1 f2 ->
  let sig1 = get_fsig f1 in
  let sig2 = get_fsig f2 in
  try sig1 = sig2 with Invalid_argument s -> false

let get_fkey : func -> id * id * typ list
= fun f -> ((get_finfo f).scope_s, get_fname f, get_param_types f)

let get_func_decl : func -> func_decl 
= fun (fname,params,ret_params,_,_) ->
  (fname, List.map (fun (x,xinfo) -> (x,xinfo.vtyp)) params, List.map (fun (x,xinfo) -> (x,xinfo.vtyp)) ret_params)

let get_all_fkeys_c : contract -> fkey BatSet.t
= fun c ->
  let funcs = get_funcs c in
  BatSet.of_list (List.map get_fkey funcs)

let get_all_fkeys : pgm -> fkey BatSet.t
= fun p ->
  List.fold_left (fun acc c ->
    BatSet.union (get_all_fkeys_c c) acc
  ) BatSet.empty p

(******************************)
(******************************)
(***** Tostring Functions *****)
(******************************)
(******************************)

let rec to_string_exp ?(report=false) exp =
  match exp with
  | Int n -> BatBig_int.to_string n
  | Real n -> string_of_float n
  | Str s ->
    if !Options.cfg then "\\\"" ^ (BatString.nreplace s "\n" "") ^ "\\\""
    else "\"" ^ (BatString.nreplace s "\n" "") ^ "\""
  | Lv lv -> to_string_lv ~report lv
  | Cast (typ,e) -> to_string_typ typ ^ "(" ^ to_string_exp ~report e ^ ")"
  | BinOp (bop,e1,e2,_) -> "(" ^ to_string_exp ~report e1 ^ " " ^ to_string_bop bop ^ " " ^ to_string_exp ~report e2 ^ ")"
  | UnOp (uop,e,_) -> "(" ^ to_string_uop uop ^ to_string_exp ~report e ^ ")" 
  | True -> "true"
  | False -> "false"
  | ETypeName etyp -> to_string_etyp etyp
  | IndexRangeAccess (base,sop,fop,_) ->
    (match sop,fop with
     | Some s, Some f ->
       to_string_lv ~report base ^ "[" ^ to_string_exp ~report s ^ ":" ^ to_string_exp ~report f ^ "]"
     | Some s, None ->
       to_string_lv ~report base ^ "[" ^ to_string_exp ~report s ^ ":" ^ "]"
     | None, Some f ->
       to_string_lv ~report base ^ "[" ^ ":" ^ to_string_exp ~report f ^ "]"
     | None,None -> assert false)
  | TypeInfo (typ,x,_) -> "type(" ^ to_string_typ typ ^ ")" ^ "." ^ x

  | IncTemp (e,prefix,_) -> if prefix then "++" ^ to_string_exp e else to_string_exp e ^ "++"
  | DecTemp (e,prefix,_) -> if prefix then "--" ^ to_string_exp e else to_string_exp e ^ "--" 
  | CondTemp (e1,e2,e3,_,_) -> "(" ^ to_string_exp e1 ^ " ? " ^ to_string_exp e2 ^ " : " ^ to_string_exp e3 ^ ")"
  | AssignTemp (lv,e,_) -> "(" ^ to_string_lv lv ^ " = " ^ to_string_exp e ^ ")"
  | CallTemp (e,args,ethop,gasop,_) ->
    to_string_exp ~report e ^
    (match ethop with None -> "" | Some e -> ".value(" ^ to_string_exp ~report e ^ ")") ^
    (match gasop with None -> "" | Some e -> ".gas(" ^ to_string_exp ~report e ^ ")") ^
    string_of_list ~first:"(" ~last:")" ~sep:", " (to_string_exp ~report) args

and to_string_exp_opt ?(report=false) exp =
  match exp with
  | Some e -> to_string_exp ~report e
  | None -> " "

and to_string_bop bop =
  match bop with
  | Add -> "+" | Sub -> "-" 
  | Mul -> "*" | Div -> "/" 
  | Mod -> "%" | Exponent -> "**"
  | GEq -> ">=" | Gt -> ">"  
  | LEq -> "<=" | Lt -> "<"
  | LAnd -> "&&" | LOr -> "||"
  | Eq -> "==" | NEq -> "!="
  | ShiftL -> "<<" | ShiftR -> ">>" 
  | BXor -> "^" | BAnd -> "&" 
  | BOr -> "|"

and to_string_uop uop =
  match uop with
  | Pos -> "+"
  | Neg -> "-"
  | LNot -> "!"
  | BNot -> "~"

and to_string_lv ?(report=false) lv =
  match lv with
  | Var (x,xinfo) ->
    if not report then x else to_string_vinfo_org ~report x xinfo.org
  | MemberAccess (e,x,xinfo,_) -> to_string_exp ~report e ^ "." ^ (if not report then x else to_string_vinfo_org ~report x xinfo.org)
  | IndexAccess (e,None,_) -> to_string_exp ~report e ^ "[]"
  | IndexAccess (e1,Some e2,_) -> to_string_exp ~report e1 ^ "[" ^ to_string_exp ~report e2 ^ "]"
  | Tuple (elst, t) ->
    if is_array t then string_of_list ~first:"[" ~last:"]" ~sep:", " (to_string_exp_opt ~report) elst
    else string_of_list ~first:"(" ~last:")" ~sep:", " (to_string_exp_opt ~report) elst

and to_string_vinfo_org ?(report=false) x org =
  match org with
  | None -> x
  | Some e -> to_string_exp ~report e

and to_string_typ typ =
  match typ with
  | ConstInt -> "int_const"
  | ConstReal -> "rational_const"
  | ConstString -> "literal_string"
  | EType etyp -> to_string_etyp etyp
  | Struct lst -> "struct " ^ string_of_list ~first:"" ~last:"" ~sep:"." Vocab.id lst
  | Mapping (etyp,typ) -> "mapping" ^ "(" ^ to_string_etyp etyp ^ " => " ^ to_string_typ typ ^ ")"
  | Mapping2 (t1,t2) -> "mapping2" ^ "(" ^ to_string_typ t1 ^ " => " ^ to_string_typ t2 ^ ")"
  | Array (typ,None) -> to_string_typ typ ^ "[]"
  | Array (typ,Some n) -> to_string_typ typ ^ "[" ^ string_of_int n ^ "]"
  | Void -> "void"
  | TupleType typs -> "Tuple" ^ string_of_list ~first:"(" ~last:")" ~sep:", " to_string_typ typs
  | FuncType (typs, ret_typs) ->
    "function" ^ " "
    ^ string_of_list ~first:"(" ~last:")" ~sep:"," to_string_typ typs ^ " "
    ^ string_of_list ~first:"returns(" ~last:")" ~sep:"," to_string_typ ret_typs

and to_string_etyp elem_typ =
  match elem_typ with
  | Contract id -> "contract " ^ id
  | Enum id -> id
  | Address -> "address"
  | AddressPayable -> "payable"
  | Bool -> "bool"
  | String -> "string"
  | UInt n -> "uint" ^ string_of_int n
  | SInt n -> "int" ^ string_of_int n
  | Bytes n -> "bytes" ^ string_of_int n
  | DBytes -> "dbytes" (* dynamically-sized byte array *)
  (* | Fixed -> "fixed"
  | UFixed -> "ufixed" *)

let rec to_string_stmt ?(report=false) stmt =
  match stmt with
  | Assign (lv,e,_) -> to_string_lv ~report lv ^ " = " ^ to_string_exp ~report e ^ ";"
  | Decl lv -> to_string_typ (get_type_lv lv) ^ " " ^ to_string_lv lv ^ ";"
  | Seq (s1,s2) -> to_string_stmt ~report s1 ^ "" ^ "\n" ^ "    " ^ to_string_stmt ~report s2
  | Call (None, e, exps, ethop, gasop, _) ->
    to_string_exp ~report e ^
    (match ethop with None -> "" | Some e -> ".value(" ^ to_string_exp ~report e ^ ")") ^
    (match gasop with None -> "" | Some e -> ".gas(" ^ to_string_exp ~report e ^ ")") ^
    string_of_list ~first:"(" ~last:")" ~sep:", " (to_string_exp ~report) exps ^ ";"

  | Call (Some lv, e, exps, ethop, gasop, _) ->
    if report && BatString.starts_with (to_string_lv lv) "Tmp" then
      to_string_lv ~report lv
    else
      to_string_lv ~report lv ^ " = " ^ to_string_exp ~report e ^
      (match ethop with None -> "" | Some e -> ".value(" ^ to_string_exp ~report e ^ ")") ^
      (match gasop with None -> "" | Some e -> ".gas(" ^ to_string_exp ~report e ^ ")") ^
      string_of_list ~first:"(" ~last:")" ~sep:", " (to_string_exp ~report) exps ^ ";"

  | Skip -> "skip;"
  | If (e,s1,s2,_) ->
    "if" ^ "(" ^ to_string_exp ~report e ^ ")" ^ "{" ^ to_string_stmt ~report s1 ^ "}" ^ " " ^
    "else" ^ "{" ^ to_string_stmt ~report s2 ^ "}" 
  | While (e,s) -> "while" ^ "(" ^ to_string_exp ~report e ^ ")" ^ "{" ^ to_string_stmt ~report s ^ "}"
  | Break -> "break;"
  | Continue -> "continue;"
  | Return (None,_) -> "return;"
  | Return (Some e,_) -> "return " ^ to_string_exp ~report e ^ ";"
  | Throw -> "throw;"
  | Assume (e,_) -> "assume" ^ "(" ^ to_string_exp ~report e ^ ")" ^ ";"
  | Assert (e,_,_) -> "assert" ^ "(" ^ to_string_exp ~report e ^ ")" ^ ";"
  | Assembly (lst,_) ->
    "assembly" ^ string_of_list ~first:"{" ~last:"}" ~sep:", " (fst|>id) lst ^ ";"
  | PlaceHolder -> "_;"
  | Unchecked (lst,_) ->
    "unchecked {" ^ "\n" ^
     (List.fold_left (fun acc s ->
      if acc = "" then "    " ^ to_string_stmt ~report s
      else
        acc ^ "\n" ^ "    " ^ to_string_stmt ~report s
      ) "" lst) ^ "\n" ^ "}"

let rec to_string_func (id,params,ret_params,stmt,finfo) =
  "function" ^ " " ^ id ^ " " ^ to_string_params params ^
  (if List.length finfo.mod_list2 > 0 then " " ^ to_string_mods finfo.mod_list2 else "") ^
  (if List.length finfo.mod_list > 0 then " " ^ to_string_mods finfo.mod_list else "") ^
  " " ^ "returns" ^ " " ^ to_string_params ret_params ^
  " " ^ to_string_vis finfo.fvis ^
  " " ^ (if finfo.is_payable then "payable" else "") ^ " " ^ "{" ^ "\n" ^
  "    " ^ to_string_stmt stmt ^ "\n" ^ "  " ^ "}" ^ "\n"
 
and to_string_param (id,vinfo) = to_string_typ vinfo.vtyp ^ " " ^ id
and to_string_params params = string_of_list ~first:"(" ~last:")" ~sep:", " to_string_param params

and to_string_exps exps = string_of_list ~first:"(" ~last:")" ~sep:", " to_string_exp exps
and to_string_mod (id,exps,loc) = if List.length exps = 0 then id else id ^ to_string_exps exps
and to_string_mods mods = string_of_list ~first:"" ~last:"" ~sep:" " to_string_mod mods

and to_string_vis vis =
 match vis with
 | Public -> "public"
 | Internal -> "internal"
 | External -> "external"
 | Private -> "private"

let to_string_state_var_decl decl =
  match decl with
  | (id,None,vinfo) -> to_string_typ vinfo.vtyp ^ " " ^ id ^ ";"
  | (id,Some e,vinfo) -> to_string_typ vinfo.vtyp ^ " " ^ id ^ " = " ^ to_string_exp e ^ ";" 

let to_string_var_decl = to_string_param

let to_string_structure (id,decls) =
  "struct" ^ " " ^ id ^ "{" ^ "\n" ^
  (string_of_list ~first:"    " ~last:";" ~sep:";\n    " to_string_var_decl decls) ^
  "\n" ^ "  " ^ "}" ^ "\n"

let to_string_enum (id,mems) =
  "enum" ^ " " ^ id ^ (string_of_list ~first:" {" ~last:"}" ~sep:", " Vocab.id mems)

let to_string_contract (id, decls, structs, enums, func_defs, _) =
  "contract" ^ " " ^ id ^ "{" ^ "\n" ^
  (if decls = [] then ""  
   else string_of_list ~first:"  " ~last:"\n\n" ~sep:"\n  " to_string_state_var_decl decls) ^
  (if structs = [] then ""
   else string_of_list ~first:"  " ~last:"\n\n" ~sep:"\n  " to_string_structure structs) ^
  (if enums = [] then ""
   else string_of_list ~first:"  " ~last:"\n\n" ~sep:"\n  " to_string_enum enums) ^
  string_of_list ~first:"  " ~last:"\n" ~sep:"\n  " to_string_func func_defs ^ "}"

let to_string_pgm contracts =
  string_of_list ~first:"" ~last:"" ~sep:"\n\n" to_string_contract contracts

let to_string_fsig (fname,typs) =
  fname ^ ", " ^ (string_of_list ~first:"{" ~last:"}" ~sep:", " to_string_typ typs)

let to_string_fkey (cname,fname,typs) =
  "(" ^ cname ^ ", " ^ fname ^ ", " ^ (string_of_list ~first:"[" ~last:"]" ~sep:", " to_string_typ typs) ^ ")"

let to_string_fkey2 (cname,fname,typs) =
  "(" ^ cname ^ "/" ^ fname ^ "/" ^ (string_of_list ~first:"[" ~last:"]" ~sep:"_" to_string_typ typs) ^ ")"

let to_string_cfg ?(name="G") : cfg -> string
= fun cfg ->
  "digraph " ^ name ^ "{" ^ "\n" ^
  "{" ^ "\n" ^
  "node [shape=box]" ^ "\n" ^
  G.fold_vertex (fun v acc ->
    let str_v = Node.to_string v in
    let stmt = to_string_stmt (find_stmt v cfg) in
    let colored = 
      if is_loophead v cfg then " style=filled color=grey shape=oval" else
      if is_loopexit v cfg then " style=filled color=grey shape=diamond" else
      if is_callnode v cfg then " style=filled color=yellow" 
      else ""
    in
    acc ^ str_v ^ " [label=\"" ^ str_v ^ ": " ^ stmt ^ "\"" ^ colored ^ "]" ^ "\n"
  ) cfg.graph ""
  ^
  "}" ^ "\n" ^
  G.fold_edges (fun v1 v2 acc ->
    acc ^ Node.to_string v1 ^ " -> " ^ Node.to_string v2 ^ "\n"
  ) cfg.graph ""
  ^
  "}" ^ "\n\n"

let to_string_cfg_f : func -> string
= fun func -> to_string_cfg ~name:(get_fname func) (get_cfg func)

let to_string_cfg_c : contract -> string
= fun contract ->
  List.fold_left (fun acc f ->
    acc ^ to_string_cfg_f f
  ) "" (get_funcs contract)

let to_string_cfg_p : pgm -> string
= fun p ->
  List.fold_left (fun acc c ->
    acc ^ to_string_cfg_c c
  ) "" p

let to_string_path : node list -> string
= fun path -> string_of_list ~first:"[" ~last:"]" ~sep:"->" Node.to_string path

let to_string_paths : node list BatSet.t -> string
= fun paths -> string_of_set ~first:"{" ~last:"}" ~sep:",\n" to_string_path paths

let print_path : node list -> unit
= fun path -> print_endline (to_string_path path)

let print_paths : node list BatSet.t -> unit
= fun paths -> print_endline (to_string_paths paths) 

(******************************)
(******************************)
(***** Built-in Functions *****)
(******************************)
(******************************)

let is_require exp =
  match exp with
  | Lv (Var ("require",_)) -> true
  | _ -> false

let is_assert exp =
  match exp with
  | Lv (Var ("assert",_)) -> true
  | _ -> false

let is_revert exp =
  match exp with
  | Lv (Var ("revert",_)) -> true
  | _ -> false

(***********************)
(***********************)
(***** Other Utils *****)
(***********************)
(***********************)

let rec replace_exp : exp -> exp -> exp -> exp 
= fun exp target replacement ->
  match exp with
  | Int _ | Real _ | Str _ -> exp
  | Lv lv when exp = target -> replacement
  | Lv lv -> exp
  | Cast (typ,e) -> Cast (typ, replace_exp e target replacement)
  | BinOp (bop,e1,e2,einfo) -> BinOp (bop, replace_exp e1 target replacement, replace_exp e2 target replacement, einfo)
  | UnOp (uop,e,typ) -> UnOp (uop, replace_exp e target replacement, typ)
  | True | False -> exp
  | ETypeName _ -> exp
  | IndexRangeAccess (base,sop,fop,einfo) ->
    let f eop = match eop with Some e -> Some (replace_exp e target replacement) | None -> None in
    IndexRangeAccess (base, f sop, f fop, einfo)
  | TypeInfo _ -> exp
  | AssignTemp _ | CondTemp _
  | IncTemp _ | DecTemp _ | CallTemp _ -> failwith "replace_exp"

let equal_typ : typ -> typ -> bool
= fun t1 t2 -> t1 = t2

exception NoParameters

let params_to_lv params =
  if (List.length params = 1) then
    let (x,vinfo) = List.hd params in
    Var (x,vinfo) else 
  if (List.length params > 1) then
    let eops = List.map (fun (x,vinfo) -> Some (Lv (Var (x,vinfo)))) params in
    let tuple_typ = TupleType (List.map (fun (_,vinfo) -> vinfo.vtyp) params) in
    Tuple (eops,tuple_typ)
  else
    raise NoParameters

let args_to_exp : exp list -> exp
= fun args ->
  if (List.length args = 1) then
    List.hd args else
  if (List.length args > 1) then
    let eops = List.map (fun e -> Some e) args in
    let tuple_typ = TupleType (List.map get_type_exp args) in
    Lv (Tuple (eops,tuple_typ))
  else
    raise NoParameters

let blk_keyword_vars =
  ["block.basefee";  "block.chainid"; "block.coinbase"; "block.difficulty"; "block.gaslimit";
   "block.number"; "block.timestamp"; "now"]

let keyword_vars =
  blk_keyword_vars @
  ["msg.data"; "msg.data.length"; "msg.sender"; "msg.value"; "msg.gas"; "msg.sig";
   "this";
   "tx.gasprice"; "tx.origin"]

let is_balance_keyword lv =
  match lv with
  | MemberAccess (e,id,_,_)
    when (is_address (get_type_exp e) || is_contract (get_type_exp e))
         && BatString.equal id "balance"
    -> true
  | _ -> false

let init_funcs = ["array_init"; "dbytes_init"; "string_init"; "contract_init"; "struct_init"; "struct_init2"]

(* suicide is disallowed since solc 0.5.0 *)
let built_in_funcs =
  ["abi.encode"; "abi.decode"; "abi.encodePacked"; "abi.encodeWithSignature"; "abi.encodeWithSelector";
   "revert"; "keccak256"; "sha3"; "sha256"; "ripemd160"; "delete"; 
   "selfdestruct"; "suicide"; "ecrecover"; "addmod"; "mulmod";
   "blockhash"; "block.blockhash"]

let max_256bit =
  let pow = BatBig_int.pow (BatBig_int.of_string "2") (BatBig_int.of_string "256") in
  let one = BatBig_int.of_string "1" in
  BatBig_int.sub pow one

let max_of_n_bits n =
  let pow = BatBig_int.pow (BatBig_int.of_int 2) (BatBig_int.of_int n) in
  let one = BatBig_int.of_int 1 in
  BatBig_int.sub pow one

let rec var_lv : lv -> var BatSet.t
= fun lv ->
  match lv with
  | Var (x,xinfo) -> BatSet.singleton (x,xinfo.vtyp)
  | MemberAccess (e,x,xinfo,_) -> BatSet.add (x,xinfo.vtyp) (var_exp e)
  | IndexAccess (e1,Some e2,_) -> BatSet.union (var_exp e1) (var_exp e2)
  | IndexAccess (e,None,_) -> var_exp e
  | Tuple (eops,_) ->
    List.fold_left (fun acc eop ->
      match eop with
      | None -> acc
      | Some e -> BatSet.union (var_exp e) acc
    ) BatSet.empty eops

and var_exp : exp -> var BatSet.t
= fun exp ->
  match exp with
  | Int _ | Real _ | Str _ -> BatSet.empty
  | Lv lv ->
    if List.mem (to_string_lv lv) keyword_vars then
      BatSet.singleton (to_string_lv lv, get_type_lv lv)
    else var_lv lv
  | Cast (_,e) -> var_exp e
  | BinOp (_,e1,e2,_) -> BatSet.union (var_exp e1) (var_exp e2)
  | UnOp (_,e,_) -> var_exp e
  | True | False -> BatSet.empty
  | ETypeName _ -> BatSet.empty
  | IndexRangeAccess (base,sop,fop,_) ->
    BatSet.union (var_lv base) (BatSet.union (var_eop sop) (var_eop fop))
  | TypeInfo _ -> BatSet.empty
  | IncTemp (e,_,_) | DecTemp (e,_,_) -> var_exp e
  | CallTemp (e,exps,ethop,gasop,_) -> var_call (None,e,exps,ethop,gasop)
  | CondTemp (e1,e2,e3,_,_) -> BatSet.union (var_exp e1) (BatSet.union (var_exp e2) (var_exp e3))
  | _ -> failwith ("var_exp: temp expressions encountered - " ^ to_string_exp exp)

and var_eop eop =
  match eop with
  | Some e -> var_exp e
  | None -> BatSet.empty

and var_call (lvop,e,exps,ethop,gasop) =
  let set1 = match lvop with None -> BatSet.empty | Some lv -> var_lv lv in
  let set2 =
    (match e with
     | e when List.mem (to_string_exp e) built_in_funcs -> BatSet.empty
     | Lv (MemberAccess (Lv (Var (v,vinfo)),fname,_,_)) (* safemath.add(...) *)
       when is_contract vinfo.vtyp || v = "super" -> BatSet.empty
     | Lv (MemberAccess (arg,fname,_,_)) -> (* x.add(...), x[y].add(...) *)
       var_exp arg
     | _ -> BatSet.empty)
  in
  let set3 = List.fold_left (fun acc e' -> BatSet.union (var_exp e') acc) BatSet.empty exps in
  let set4 = match ethop with None -> BatSet.empty | Some eth -> var_exp eth in
  let set5 = match gasop with None -> BatSet.empty | Some gas -> var_exp gas in
  BatSet.union set1 (BatSet.union set2 (BatSet.union set3 (BatSet.union set4 set5)))


let rec var_stmt : stmt -> var BatSet.t
= fun stmt ->
  match stmt with
  | Assign (lv,exp,_) -> BatSet.union (var_lv lv) (var_exp exp)
  | Decl lv -> var_lv lv
  | Call (lvop,e,exps,ethop,gasop,_) -> var_call (lvop,e,exps,ethop,gasop)
  | Skip -> BatSet.empty
  | Return (None,_) -> BatSet.empty
  | Return (Some e,_) -> var_exp e
  | Throw -> BatSet.empty
  | Assume (e,_) | Assert (e,_,_) -> var_exp e
  | Assembly _ -> BatSet.empty
  | If (e,s1,s2,_) ->
    let set1 = var_exp e in
    let set2 = var_stmt s1 in
    let set3 = var_stmt s2 in
    BatSet.union set1 (BatSet.union set2 set3)
  | Seq (s1,s2) -> BatSet.union (var_stmt s1) (var_stmt s2)
  | While (e,s) -> BatSet.union (var_exp e) (var_stmt s)
  | Break | Continue | PlaceHolder -> BatSet.empty
  | Unchecked (lst,loc) ->
    List.fold_left (fun acc s ->
      BatSet.union (var_stmt s) acc
    ) BatSet.empty lst

module OrderedType = struct
  type t = BatBig_int.t
  let compare = BatBig_int.compare
end

module BigIntSet = BatSet.Make (OrderedType)

let rec int_lv : lv -> BigIntSet.t
= fun lv ->
  match lv with
  | Var _ -> BigIntSet.empty
  | MemberAccess (e,_,_,_) -> int_exp e
  | IndexAccess (e1,Some e2,_) -> BigIntSet.union (int_exp e1) (int_exp e2)
  | IndexAccess (e,None,_) -> int_exp e
  | Tuple (eops,_) ->
    List.fold_left (fun acc eop ->
      match eop with
      | None -> acc
      | Some e -> BigIntSet.union (int_exp e) acc
    ) BigIntSet.empty eops

and int_exp : exp -> BigIntSet.t
= fun exp ->
  match exp with
  | Int n -> BigIntSet.singleton n
  | Real _ | Str _ -> BigIntSet.empty
  | Lv lv -> int_lv lv
  | Cast (_,e) -> int_exp e
  | BinOp (_,e1,e2,_) -> BigIntSet.union (int_exp e1) (int_exp e2)
  | UnOp (_,e,_) -> int_exp e
  | True | False -> BigIntSet.empty
  | ETypeName _ -> BigIntSet.empty
  | _ -> failwith "int_exp: temp expressions encountered"


let preceding_typ : typ -> typ -> typ
= fun t1 t2 ->
  if t1=t2 then t1
  else
   (match t1,t2 with
    | EType String, ConstString -> t1
    | EType (UInt n1), EType (UInt n2) -> EType (UInt (max n1 n2))
    | EType (SInt n1), EType (SInt n2) -> EType (SInt (max n1 n2))
    | EType (SInt n1), EType (UInt n2) when n1>n2 -> t1
    | EType (SInt n1), EType (UInt n2) when n1<=n2 -> raise (Failure "preceding_typ : intX1 and uintX2 are not convertible if X1<=X2")
    | EType (UInt n1), EType (SInt n2) when n1<n2 -> t2
    | EType (UInt n1), EType (SInt n2) when n1>=n2 -> t1

    | ConstInt, EType AddressPayable -> t2
    | ConstInt, EType Address -> t2
    | EType Address, ConstInt -> t1
    | EType AddressPayable, ConstInt -> t1

    | EType (Contract s), ConstInt -> t1
    | EType Address, EType (Contract s) -> t1
    | EType (Contract s), EType Address -> t2
    | EType Bytes _, ConstInt -> t1
    | ConstInt, EType Bytes _ -> t2
    | Array (t1,None), Array (t2, Some n) when t1=t2 -> Array (t1,None)
    | EType (Contract id1), EType (Contract id2) -> t2
    | ConstString, EType Bytes _ -> t2
    | ConstString, EType DBytes -> t2
    | EType Bytes _, ConstString -> t1
    | EType DBytes, ConstString -> t1
    | EType Address, EType AddressPayable -> t1
    | EType AddressPayable, EType Address -> t2
    | t1,t2 -> raise (Failure ("preceding_typ : " ^ (to_string_typ t1) ^ " vs. " ^ (to_string_typ t2))))

(* currently, casting is performed in the vc generation step. *)
let rec folding : exp -> exp
= fun exp ->
  match exp with
  | Int n -> Int n
  | BinOp (Add,Int n1,Int n2,einfo) -> Int (BatBig_int.add n1 n2)
  | BinOp (Sub,Int n1,Int n2,einfo) -> Int (BatBig_int.sub n1 n2)
  | BinOp (Mul,Int n1,Int n2,einfo) -> Int (BatBig_int.mul n1 n2)
  | BinOp (Div,Int n1,Int n2,einfo) -> Int (BatBig_int.div n1 n2)
  | BinOp (Mod,Int n1,Int n2,einfo) -> Int (BatBig_int.modulo n1 n2)
  | BinOp (Exponent,Int n1,Int n2,einfo) -> Int (BatBig_int.pow n1 n2)
  | BinOp (bop,e1,e2,einfo) -> BinOp (bop, folding e1, folding e2, einfo) 
  | _ -> failwith "folding"

let rec constant_folding : exp -> exp
= fun exp ->
  let exp' = folding exp in
  if BatString.equal (to_string_exp exp) (to_string_exp exp') then exp'
  else constant_folding exp'

let common_typ : exp -> exp -> typ 
= fun e1 e2 ->
  let t1,t2 = get_type_exp e1, get_type_exp e2 in
  if t1=t2 then t1 
  else
   (match t1,t2 with
    | ConstInt, EType (UInt n) ->
      let n' = bit_unsigned_of_int (get_bigint (constant_folding e1)) 8 in
      EType (UInt (max n n'))
    | EType (UInt n), ConstInt ->
      let n' = bit_unsigned_of_int (get_bigint (constant_folding e2)) 8 in
      EType (UInt (max n n'))
    | ConstInt, EType (SInt n) ->
      let n' = bit_signed_of_int (get_bigint (constant_folding e1)) 8 in
      EType (SInt (max n n'))
    | EType (SInt n), ConstInt ->
      let n' = bit_signed_of_int (get_bigint (constant_folding e2)) 8 in
      EType (SInt (max n n'))
    | _ -> preceding_typ t1 t2)


let mk_einfo : typ -> einfo
= fun t -> {eloc=dummy_loc; etyp=t; eid=(-1)}

let mk_finfo : contract -> finfo
= fun c ->
  {is_constructor = false;
   is_payable = false;
   is_modifier = false;
   mod_list = [];
   mod_list2 = []; (* modifier by inheritance *)
   param_loc = dummy_loc;
   ret_param_loc = dummy_loc;
   fvis = Public;
   mutability = NonPayable;
   fid = (-1);
   floc = dummy_loc;
   scope = (get_cinfo c).numid;
   scope_s = get_cname c;
   org_scope_s = get_cname c;
   cfg = empty_cfg}

let mk_index_access : exp -> exp -> exp
= fun e1 e2 ->
  let _ = assert (is_usual_mapping (get_type_exp e1) || is_usual_allowance (get_type_exp e1)) in
  let _ = assert (is_address (get_type_exp e2)) in
  Lv (IndexAccess (e1, Some e2, range_typ (get_type_exp e1)))

let mk_member_access : exp -> var -> exp
= fun e (x,t) ->
  Lv (MemberAccess (e, x, mk_vinfo ~typ:t (), t))

let mk_eq : exp -> exp -> exp
= fun e1 e2 -> BinOp (Eq, e1, e2, mk_einfo (EType Bool))

let mk_neq : exp -> exp -> exp
= fun e1 e2 -> BinOp (NEq, e1, e2, mk_einfo (EType Bool)) 

let mk_ge : exp -> exp -> exp
= fun e1 e2 -> BinOp (GEq, e1, e2, mk_einfo (EType Bool))

let mk_gt : exp -> exp -> exp
= fun e1 e2 -> BinOp (Gt, e1, e2, mk_einfo (EType Bool))

let mk_and : exp -> exp -> exp
= fun e1 e2 ->
  let _ = assert (is_bool (get_type_exp e1)) in
  let _ = assert (is_bool (get_type_exp e2)) in
  BinOp (LAnd, e1, e2, mk_einfo (EType Bool))

let mk_or : exp -> exp -> exp
= fun e1 e2 ->
  let _ = assert (is_bool (get_type_exp e1)) in
  let _ = assert (is_bool (get_type_exp e2)) in
  BinOp (LOr, e1, e2, mk_einfo (EType Bool))

let mk_add : exp -> exp -> exp
= fun e1 e2 -> BinOp (Add, e1, e2, mk_einfo (common_typ e1 e2))

let mk_sub : exp -> exp -> exp
= fun e1 e2 -> BinOp (Sub, e1, e2, mk_einfo (common_typ e1 e2))

let mk_mul : exp -> exp -> exp
= fun e1 e2 -> BinOp (Mul, e1, e2, mk_einfo (common_typ e1 e2))

let mk_div : exp -> exp -> exp
= fun e1 e2 -> BinOp (Div, e1, e2, mk_einfo (common_typ e1 e2))

let mk_not : exp -> exp
= fun e -> UnOp (LNot, e, EType Bool)

(* rename local variables  with given labels *)
let rec rename_lv : string -> var list -> lv -> lv
= fun lab gvars lv ->
  match lv with
  | Var (x,xinfo) ->
    if List.mem (x,xinfo.vtyp) gvars then lv
    else if List.mem x ["@TU"; "@Invest"; "@Invest_sum"; "@extern_called"; "@CA"] then lv
    else Var (x ^ lab, xinfo)
  | MemberAccess (e,x,xinfo,typ) when is_enum typ -> lv
  | MemberAccess (e,x,xinfo,typ) -> MemberAccess (rename_e lab gvars e, x, xinfo, typ)
  | IndexAccess (e,None,_) -> failwith "rename_lv"
  | IndexAccess (e1,Some e2,typ) -> IndexAccess (rename_e lab gvars e1, Some (rename_e lab gvars e2), typ)
  | Tuple (eoplst,typ) ->
    let eoplst' =
      List.map (fun eop ->
        match eop with
        | None -> None
        | Some e -> Some (rename_e lab gvars e)
      ) eoplst
    in
    Tuple (eoplst',typ)

and rename_e : string -> var list -> exp -> exp
= fun lab gvars exp ->
  match exp with
  | Int _ | Real _ | Str _ -> exp
  | Lv lv ->
    if List.mem (to_string_lv lv) keyword_vars || to_string_lv lv = "abi" then exp
    else Lv (rename_lv lab gvars lv)
  | Cast (typ,e) -> Cast (typ, rename_e lab gvars e)
  | BinOp (bop,e1,e2,einfo) ->
    BinOp (bop, rename_e lab gvars e1, rename_e lab gvars e2, einfo)
  | UnOp (uop,e,typ) -> UnOp (uop, rename_e lab gvars e, typ)
  | True | False | ETypeName _ -> exp
  | IndexRangeAccess (base,sop,fop,einfo) ->
    let rename_eop eop = match eop with Some e -> Some (rename_e lab gvars e) | None -> None in
    IndexRangeAccess (rename_lv lab gvars base, rename_eop sop, rename_eop fop, einfo)
  | TypeInfo _ -> exp
  | IncTemp _ | DecTemp _ | CallTemp _
  | CondTemp _ | AssignTemp _ -> failwith "rename_e"

let rec rename_stmt : string -> var list -> id list -> stmt -> stmt
= fun lab gvars cnames stmt ->
  match stmt with
  | Assign (lv,e,loc) ->  Assign (rename_lv lab gvars lv, rename_e lab gvars e, loc)
  | Decl lv -> Decl (rename_lv lab gvars lv)
  | Call (lvop, (Lv (Var ("@extern_log",_)) as e), args,ethop,gasop,loc) ->
    let args' = (List.hd args)::(List.map (rename_e lab gvars) (List.tl args)) in
    Call (lvop,e,args',ethop,gasop,loc)
  | Call (lvop,e,args,ethop,gasop,loc) ->
    let lvop' = match lvop with None -> lvop | Some lv -> Some (rename_lv lab gvars lv) in
    let e' =
      match e with (* rename only for contract object cases *)
      | Lv (MemberAccess (Lv (Var (x,xinfo)) as obj, fname, fname_info, typ)) ->
        if List.mem x cnames || x = "super" then e (* static call *)
        else Lv (MemberAccess (rename_e lab gvars obj, fname, fname_info, typ))
      | _ -> e (* built-in functions, static call without prefixes *)
    in
    let args' =
      if to_string_exp e = "struct_init" || to_string_exp e = "contract_init" then
        (* the first arg is struct/contract name; see preprocess.ml *)
        (List.hd args)::(List.map (rename_e lab gvars) (List.tl args))
      else List.map (rename_e lab gvars) args
    in
    let ethop' = match ethop with None -> ethop | Some e -> Some (rename_e lab gvars e) in
    let gasop' = match gasop with None -> gasop | Some e -> Some (rename_e lab gvars e) in
    Call (lvop',e',args',ethop',gasop',loc)
  | Skip -> stmt
  | Return (None,_) -> stmt
  | Return (Some e,loc) -> Return (Some (rename_e lab gvars e), loc)
  | Throw -> stmt
  | Assume (e,loc) -> Assume (rename_e lab gvars e, loc)
  | Assert (e,vtyp,loc) -> Assert (rename_e lab gvars e, vtyp, loc)
  | Assembly (lst,loc) ->
    let gnames = List.map fst gvars in
    let lst' =
      List.map (fun (x,refid) ->
        if List.mem x gnames then (x,refid)
        else (x ^ lab, refid)
      ) lst
    in
    Assembly (lst',loc)
  | If (e,s1,s2,i) -> If (rename_e lab gvars e, rename_stmt lab gvars cnames s1, rename_stmt lab gvars cnames s2, i)
  | Seq (s1,s2) -> Seq (rename_stmt lab gvars cnames s1, rename_stmt lab gvars cnames s2)
  | While (e,s) -> While (rename_e lab gvars e, rename_stmt lab gvars cnames s)
  | Break | Continue | PlaceHolder -> stmt
  | Unchecked (lst,loc) ->
    let lst' = List.map (rename_stmt lab gvars cnames) lst in
    Unchecked (lst', loc)

let no_eth_gas_modifiers stmt =
  match stmt with
  | Call (_,_,_,None,None,_) -> true
  | Call _ -> false
  | _ -> failwith "no_eth_gas_modifiers"

let tmpvar_cnt = ref 0
let tmpvar = "Tmp"

let gen_tmpvar ?(org=None) ?(loc=(-1)) typ =
  tmpvar_cnt:=!tmpvar_cnt+1;
  Var (tmpvar^(string_of_int !tmpvar_cnt), mk_vinfo ~typ:typ ~org:org ~loc:(mk_loc ~line:loc ~finish_line:loc ()) ())

let ca = (* used in exploit mode *)
  let msg_sender = Lv (Var ("msg.sender", mk_vinfo ~typ:(EType Address) ())) in
  ("@CA", mk_vinfo ~typ:(EType Address) ~org:(Some msg_sender) ())

let orgname : var -> string
= fun x ->
  try fst (BatString.split (fst x) ~by:"__")
  with Not_found -> (fst x)

let get_name_userdef : typ -> id
= fun t ->
  match t with
  | Struct lst -> string_of_list ~first:"" ~last:"" ~sep:"." Vocab.id lst
  | EType (Enum s) -> s
  | EType (Contract s) -> s
  | _ -> failwith ("get_name_userdef : " ^ to_string_typ t)
