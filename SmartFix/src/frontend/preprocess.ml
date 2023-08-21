open Lang
open Vocab
open CallGraph
open Options

(************************************)
(************************************)
(*** Move state_var_init to Cnstr ***)
(************************************)
(************************************)

let decl_to_stmt : state_var_decl -> stmt
= fun (id,eop,vinfo) ->
  (match eop with
   | None -> Decl (Var (id,vinfo))
   | Some e -> Assign (Var (id,vinfo), e, vinfo.vloc))

let move_f decls func =
  if is_constructor func then (* add initializations of decls to constructors *)
    let inits = List.fold_left (fun acc decl -> Seq (acc, decl_to_stmt decl)) Skip decls in
    let body = get_body func in
    let body' = Seq (inits, body) in
    update_body body' func
  else func

let move_c (cid, decls, structs, enums, funcs, cinfo) =
  (cid, decls, structs, enums, List.map (move_f decls) funcs, cinfo)

let move_p contracts = List.map move_c contracts

let move_decl_to_cnstr pgm = move_p pgm

(***********************)
(***********************)
(*** Replace TemExps ***)
(***********************)
(***********************)

let separator = "__@"

let rec hastmp_lv lv =
  match lv with
  | Var _ -> false
  | MemberAccess (e,_,_,_) -> hastmp_e e
  | IndexAccess (e,None,_) -> hastmp_e e
  | IndexAccess (e1,Some e2,_) -> hastmp_e e1 || hastmp_e e2
  | Tuple (eoplst,_) -> List.exists (fun eop -> match eop with None -> false | Some e -> hastmp_e e) eoplst

and hastmp_e e =
  match e with
  | Int _ | Real _ | Str _ -> false 
  | Lv lv -> hastmp_lv lv
  | Cast (_,e) -> hastmp_e e
  | BinOp (_,e1,e2,_) -> hastmp_e e1 || hastmp_e e2
  | UnOp (_,e,_) -> hastmp_e e
  | True | False | ETypeName _ -> false
  | IndexRangeAccess (base,sop,fop,_) ->
    hastmp_lv base
    || (match sop with None -> false | Some s -> hastmp_e s)
    || (match fop with None -> false | Some f -> hastmp_e f)
  | TypeInfo _ -> false
  | AssignTemp _ | CondTemp _ | IncTemp _ | DecTemp _ | CallTemp _ -> true

and hastmp_s s =
  match s with
  | Assign (lv,e,_) -> hastmp_lv lv || hastmp_e e
  | Decl _ -> false 
  | Seq (s1,s2) -> hastmp_s s1 || hastmp_s s2
  | Call (lvop,e,params,ethop,gasop,_) ->
    let b1 = match lvop with None -> false | Some lv -> hastmp_lv lv in
    let b2 = hastmp_e e in
    let b3 = List.exists hastmp_e params in
    let b4 = match ethop with None -> false | Some e -> hastmp_e e in
    let b5 = match gasop with None -> false | Some e -> hastmp_e e in
    b1 || b2 || b3 || b4 || b5
  | Skip -> false
  | If (e,s1,s2,_) -> hastmp_e e || hastmp_s s1 || hastmp_s s2
  | While (e,s) -> hastmp_e e || hastmp_s s
  | Break -> false
  | Continue -> false
  | Return (None,_) -> false
  | Return (Some e,_) -> hastmp_e e 
  | Throw -> false
  | Assume (e,_) -> hastmp_e e
  | Assert (e,_,_) -> hastmp_e e
  | Assembly _ | PlaceHolder -> false
  | Unchecked (lst,loc) -> List.exists hastmp_s lst

let hastmp_f (_,_,_,stmt,_) = hastmp_s stmt
let hastmp_c (_,_,_,_,funcs,_) = List.exists hastmp_f funcs
let hastmp_p contracts = List.exists hastmp_c contracts
let hastmp p = hastmp_p p

(* Given a exp, returns a pair of (replaced exp,new stmt) *)
let rec replace_tmpexp_e : exp -> exp * stmt
= fun exp ->
  match exp with
  | Int n -> (exp,Skip)
  | Real n -> (exp,Skip)
  | Str s -> (exp,Skip)
  | Lv lv ->
    let (lv',s) = replace_tmpexp_lv lv in
    (Lv lv',s)
  | Cast (typ,e) ->
    let (e',s) = replace_tmpexp_e e in
    (Cast (typ,e'),s)
  | BinOp (bop,e1,e2,einfo) ->
    let (e1',s1) = replace_tmpexp_e e1 in
    let (e2',s2) = replace_tmpexp_e e2 in
    (BinOp (bop,e1',e2',einfo), Seq (s1,s2))
  | UnOp (uop,e,typ) ->
    let (e',s) = replace_tmpexp_e e in
    (UnOp (uop,e',typ), s)
  | True | False -> (exp,Skip)
  | ETypeName _ -> (exp,Skip)
  | IndexRangeAccess (base,sop,fop,einfo) ->
    let (base',s1) = replace_tmpexp_lv base in
    let (sop',s2) = match sop with Some start -> let (e,s) = replace_tmpexp_e start in (Some e,s) | None -> (None,Skip) in
    let (fop',s3) = match fop with Some fin -> let (e,s) = replace_tmpexp_e fin in (Some e,s) | None -> (None,Skip) in
    (IndexRangeAccess (base',sop',fop',einfo), Seq (s1,Seq(s2,s3)))
  | TypeInfo _ -> (exp,Skip)
  | IncTemp (Lv lv,prefix,loc) when prefix ->
    let typ = get_type_lv lv in
    (Lv lv,Assign (lv, BinOp (Add,Lv lv,Int (BatBig_int.of_int 1),{eloc=loc; etyp=typ; eid=0}),loc)) 
  | IncTemp (Lv lv,_,loc) -> (* postfix case *)
    let typ = get_type_lv lv in
    let tmpvar = gen_tmpvar typ in
    (Lv tmpvar,Seq (Assign (tmpvar, Lv lv, loc),
                    Assign (lv, BinOp (Add,Lv lv,Int (BatBig_int.of_int 1),{eloc=loc; etyp=typ; eid=0}),loc)))
  | DecTemp (Lv lv,prefix,loc) when prefix ->
    let typ = get_type_lv lv in
    (Lv lv,Assign (lv, BinOp (Sub,Lv lv,Int (BatBig_int.of_int 1),{eloc=loc; etyp=typ; eid=0}),loc)) 
  | DecTemp (Lv lv,_,loc) -> (* postfix case *)
    let typ = get_type_lv lv in
    let tmpvar = gen_tmpvar typ in
    (Lv tmpvar,Seq (Assign (tmpvar, Lv lv, loc),
                    Assign (lv, BinOp (Sub,Lv lv,Int (BatBig_int.of_int 1),{eloc=loc; etyp=typ; eid=0}),loc)))
  | CallTemp (Lv (MemberAccess (Cast (t,e),id,id_info,typ)), params, ethop, gasop, einfo) -> (* ... := cast(y).f(33) *)
    let tmpvar = gen_tmpvar ~org:(Some (Cast (t,e))) t in
    let exp' = CallTemp (Lv (MemberAccess (Lv tmpvar,id,id_info,typ)), params, ethop, gasop, einfo) in
    let new_stmt = Assign (tmpvar, Cast (t,e), einfo.eloc) in
    (exp', new_stmt)
  | CallTemp (e, params, ethop, gasop, einfo) ->
    if is_tuple einfo.etyp then
      let tmpvars = List.map (gen_tmpvar ~org:(Some exp) ~loc:einfo.eloc.line) (tuple_elem_typs einfo.etyp) in
      let eoplst = List.map (fun tmp -> Some (Lv tmp)) tmpvars in
      let tuple = Tuple (eoplst, einfo.etyp) in
      (Lv tuple, Call (Some tuple, e, params, ethop, gasop, einfo.eloc))
    else
      let tmpvar = gen_tmpvar ~org:(Some exp) ~loc:einfo.eloc.line einfo.etyp in
      (Lv tmpvar, Call (Some tmpvar, e, params, ethop, gasop, einfo.eloc))
  | CondTemp (e1,e2,e3,typ,loc) ->
    (match e2,e3 with
     | Lv (Tuple (eops1,t1)), Lv (Tuple (eops2,t2)) ->
       let _ = assert (t1 = t2) in
       let tmpvars = List.map (gen_tmpvar ~org:(Some exp)) (tuple_elem_typs t1) in
       let tuple = Tuple (List.map (fun tmp -> Some (Lv tmp)) tmpvars, t1) in
       (Lv tuple, Seq (Decl tuple, If (e1, Assign (tuple, e2, loc), Assign (tuple, e3, loc), dummy_ifinfo)))
     | Lv (Tuple _),_ | _, Lv (Tuple _) -> assert false
     | _ ->
       let tmpvar = gen_tmpvar ~org:(Some exp) typ in
       (Lv tmpvar, Seq (Decl tmpvar, If (e1, Assign (tmpvar, e2, loc), Assign (tmpvar, e3, loc), dummy_ifinfo))))
  | AssignTemp (lv,e,loc) -> (Lv lv, Assign (lv,e,loc))
  | e -> raise (Failure ("replace_tmpexp_e : " ^ (to_string_exp e)))

and replace_tmpexp_lv : lv -> lv * stmt
= fun lv ->
  match lv with
  | Var _ -> (lv,Skip)
  | MemberAccess (Cast (t,e),id,id_info,typ) ->
    let tmpvar = gen_tmpvar ~org:(Some (Cast (t,e))) t in
    (MemberAccess (Lv tmpvar,id,id_info,typ), Assign (tmpvar,Cast (t,e),id_info.vloc))
  | MemberAccess (e,id,id_info,typ) ->
    let (e',s) = replace_tmpexp_e e in
    (MemberAccess (e',id,id_info,typ), s)
  | IndexAccess (e,None,typ) ->
    let (e',s) = replace_tmpexp_e e in
    (IndexAccess (e',None,typ), s)
  | IndexAccess (e1,Some e2,typ) ->
    let (e1',s1) = replace_tmpexp_e e1 in
    let (e2',s2) = replace_tmpexp_e e2 in
    (IndexAccess (e1',Some e2',typ), Seq (s1,s2))
  | Tuple (eoplst,typ) ->
    let (eoplst',final_s) =
      List.fold_left (fun (acc_lst,acc_s) eop ->
        match eop with
        | None -> (acc_lst@[None],acc_s)
        | Some e ->
          let (e',s) = replace_tmpexp_e e in
          (acc_lst@[Some e'], Seq (acc_s,s))
      ) ([],Skip) eoplst
    in
    (Tuple (eoplst',typ), final_s)

let replace_tmpexp_lvop : lv option -> lv option * stmt
= fun lvop ->
  match lvop with
  | None -> (None,Skip)
  | Some lv ->
    let (lv',stmt) = replace_tmpexp_lv lv in
    (Some lv',stmt)

let replace_tmpexp_eop : exp option -> exp option * stmt
= fun eop ->
  match eop with
  | None -> (None,Skip)
  | Some e ->
    let (e',stmt) = replace_tmpexp_e e in
    (Some e', stmt)

let has_value_gas_modifiers_old_solc exp =
  match exp with
  | CallTemp (Lv (MemberAccess (e,"gas",_,_)),_,None,None,_) -> true
  | CallTemp (Lv (MemberAccess (e,"value",_,_)),_,None,None,_) -> true
  | CallTemp (Lv (MemberAccess (e,"gas",_,_)),_,_,_,_) -> assert false
  | CallTemp (Lv (MemberAccess (e,"value",_,_)),_,_,_,_) -> assert false
  | _ -> false

(* e.g., given f.gas(10).value(5).gas(3) , return f *)
let rec remove_value_gas_modifiers exp =
  match exp with
  | CallTemp (Lv (MemberAccess (e,"gas",_,_)),_,_,_,_) -> remove_value_gas_modifiers e (* remove gas modifier chains, e.g., e.gas(10)(arg) => e(arg) *)
  | CallTemp (Lv (MemberAccess (e,"value",_,_)),_,_,_,_) -> remove_value_gas_modifiers e (* remove value modifier chains *)
  | _ -> exp 

(* get outer-most argument of gas modifier *)
let rec get_gasop exp =
  match exp with
  (* | Lv (MemberAccess (e,"call",_,_)) when is_address (get_type_exp e) -> Int BatBig_int.zero *) 
  | CallTemp (Lv (MemberAccess (e,"gas",_,_)),args,_,_,_) ->
    let _ = assert (List.length args = 1) in
    Some (List.hd args)
  | CallTemp (Lv (MemberAccess (e,"value",_,_)),_,_,_,_) -> get_gasop e
  | _ -> None

(* get outer-most argument of value modifier *)
let rec get_valueop exp =
  match exp with
  (* | Lv (MemberAccess (e,"call",_,_)) when is_address (get_type_exp e) -> Int BatBig_int.zero *)
  | CallTemp (Lv (MemberAccess (e,"gas",_,_)),_,_,_,_) -> get_valueop e
  | CallTemp (Lv (MemberAccess (e,"value",_,_)),args,_,_,_) ->
    let _ = assert (List.length args = 1) in
    Some (List.hd args)
  | _ -> None

let desugar_tuple (lv,e,loc) =
  match lv,e with
  | Tuple (eops1,_), Lv (Tuple (eops2,_)) ->
    List.fold_left2 (fun acc eop1 eop2 ->
      match eop1,eop2 with
      | Some (Lv lv'), Some e' -> Seq (acc, Assign (lv',e',loc))
      | None, Some e' -> acc
      | _ -> assert false
    ) Skip eops1 eops2
  | _ -> Assign (lv,e,loc)

let rec replace_tmpexp_s : stmt -> stmt
= fun stmt ->
  match stmt with
  (* E.g., (bool success, ) := msg.sender.call.value(..)(..) *)
  | Assign (lv, CallTemp (e,params,ethop,gasop,einfo), loc) ->
    Call (Some lv, e, params, ethop, gasop, loc)
  | Assign (lv,e,loc) ->
    let (lv',new_stmt1) = replace_tmpexp_lv lv in
    let (e',new_stmt2) = replace_tmpexp_e e in
    let assigns = desugar_tuple (lv',e',loc) in
    Seq (Seq (new_stmt1,new_stmt2), assigns)
  | Decl lv -> stmt
  | Seq (s1,s2) -> Seq (replace_tmpexp_s s1, replace_tmpexp_s s2)

  | Call (lvop,e,params,_,_,loc) when has_value_gas_modifiers_old_solc e ->
    let _ = assert (no_eth_gas_modifiers stmt) in (* ethop = gasop = None *)
    let ethop = get_valueop e in
    let gasop = get_gasop e in
    let e' = remove_value_gas_modifiers e in
    let (lvop',s1) = replace_tmpexp_lvop lvop in
    let (e'',s2) = replace_tmpexp_e e' in
    Seq (Seq (s1,s2), Call (lvop',e'',params,ethop,gasop,loc))

  | Call (lvop,e,params,ethop,gasop,loc) ->
    let (lvop',s1) = replace_tmpexp_lvop lvop in
    let (e',s2) = replace_tmpexp_e e in
    let (params',s3) =
      List.fold_left (fun (acc_params,acc_stmt) param ->
        let (param',s) = replace_tmpexp_e param in
        (acc_params@[param'], Seq (acc_stmt,s))
      ) ([],Skip) params
    in
    let (ethop',s4) = replace_tmpexp_eop ethop in
    let (gasop',s5) = replace_tmpexp_eop gasop in
    Seq (s1, Seq (s2, Seq (s3, Seq (s4, Seq (s5, Call (lvop',e',params',ethop',gasop',loc))))))
  | Skip -> stmt
  | If (e,s1,s2,i) ->
    let (e',new_stmt) = replace_tmpexp_e e in
    Seq (new_stmt, If (e', replace_tmpexp_s s1, replace_tmpexp_s s2, i))
  | While (e,s) ->
    let (e',new_stmt) = replace_tmpexp_e e in
    Seq (new_stmt, While (e', Seq(replace_tmpexp_s s,new_stmt)))
  | Break -> stmt
  | Continue -> stmt
  | Return (None,_) -> stmt
  | Return (Some (CallTemp (e,params,ethop,gasop,einfo)),loc) when einfo.etyp = TupleType [] ->
    let s1 = Call (None, e, params, ethop, gasop, loc) in
    let s2 = Return (None, loc) in
    Seq (s1,s2)
  | Return (Some e,loc_ret) ->
    let (e',new_stmt) = replace_tmpexp_e e in
    (match e',new_stmt with
     | Lv (Tuple ([],_)), Call (Some (Tuple ([],_)),e,args,ethop,gasop,loc) -> (* "return f()"; where f() returns void. *)
       Seq (Call (None,e,args,ethop,gasop,loc), Return (None,loc_ret))
     | _ -> Seq (new_stmt, Return (Some e',loc_ret)))
  | Throw -> stmt
  | Assume (e,loc) ->
    let (e',new_stmt) = replace_tmpexp_e e in
    Seq (new_stmt, Assume (e',loc))
  | Assert (e,vtyp,loc) ->
    let (e',new_stmt) = replace_tmpexp_e e in
    Seq (new_stmt, Assert (e',vtyp,loc))
  | Assembly _ -> stmt
  | PlaceHolder -> stmt
  | Unchecked (lst,loc) ->
    let lst' = List.map replace_tmpexp_s lst in
    Unchecked (lst',loc)

let replace_tmpexp_f : func -> func
= fun (id, params, ret_params, stmt, finfo) ->
  (id, params, ret_params, replace_tmpexp_s stmt, finfo)

let replace_tmpexp_c : contract -> contract
= fun (id, decls, structs, enums, funcs, cinfo) -> 
  (id, decls, structs, enums, List.map replace_tmpexp_f funcs, cinfo)

let replace_tmpexp_p : pgm -> pgm
= fun pgm -> List.map replace_tmpexp_c pgm

let rec loop f pgm =
  let pgm' = f pgm in
    if not (hastmp pgm') then pgm'
    else loop f pgm'

let replace_tmpexp : pgm -> pgm
= fun pgm -> loop replace_tmpexp_p pgm 

(******************)
(******************)
(** Remove Skips **)
(******************)
(******************)

let rec rmskip_s s =
  match s with
  | Seq (Skip,s) -> rmskip_s s
  | Seq (s,Skip) -> rmskip_s s
  | Seq (s1,s2) -> Seq (rmskip_s s1,rmskip_s s2)
  | If (e,s1,s2,i) -> If (e, rmskip_s s1, rmskip_s s2, i)
  | While (e,s) -> While (e,rmskip_s s)
  | Unchecked (lst,loc) -> Unchecked (List.map rmskip_s lst, loc)
  | _ -> s

let rmskip_f (fid, params, ret_params, stmt, finfo) = (fid, params, ret_params, rmskip_s stmt, finfo)
let rmskip_c (cid, decls, structs, enums, funcs, cinfo) = (cid, decls, structs, enums, List.map rmskip_f funcs, cinfo) 
let rmskip_p contracts = List.map rmskip_c contracts
let rmskip p = p |> rmskip_p |> rmskip_p |> rmskip_p

(*******************************)
(*******************************)
(** Normalize many variations **)
(*******************************)
(*******************************)

let rec norm_s ret_params stmt =
  match stmt with
  | Seq (s1,s2) -> Seq (norm_s ret_params s1, norm_s ret_params s2)
  | If (e,s1,s2,i) -> If (e, norm_s ret_params s1, norm_s ret_params s2, i)
  | While (e,s) -> While (e, norm_s ret_params s)
  | Call (lvop,
          Lv (MemberAccess (Lv (IndexAccess _) as arr, fname, fname_info, typ)),
          exps, ethop, gasop, loc) ->
    let tmp = gen_tmpvar ~org:(Some arr) (get_type_exp arr) in
    let assign = Assign (tmp, arr, loc) in
    let e' = Lv (MemberAccess (Lv tmp, fname, fname_info, typ)) in
    let call = Call (lvop, e', exps, ethop, gasop, loc) in
    Seq (assign, call)
  | Return (None,loc) -> stmt
  | Return (Some (Lv (Tuple ([],_))),loc) -> Return (None,loc) (* return (); => return; *)
  | Return (Some (Lv (Var _)), loc) -> stmt
  | Return (Some e,loc) ->
    let lv = params_to_lv ret_params in
    let assign = Assign (lv, e, loc) in
    let ret_stmt = Return (Some (Lv lv), loc) in
    let stmt' = Seq (assign, ret_stmt) in
    stmt'
  | _ -> stmt

let norm_f func =
  let ret = get_ret_params func in
  let stmt = get_body func in
  let stmt' = norm_s ret stmt in
  update_body stmt' func

let norm_c (cid, decls, structs, enums, funcs, cinfo) = (cid, decls, structs, enums, List.map norm_f funcs, cinfo) 
let norm_p contracts = List.map norm_c contracts
let normalize p = norm_p p

(***********************************)
(***********************************)
(** Handling Using-for-Directives **)
(***********************************)
(***********************************)

let find_matching_lib_name lib_funcs callee_name arg_typs =
  let matching_func =
    List.find (fun f ->
      let param_typs = get_param_types f in
      BatString.equal (get_fname f) callee_name &&
      List.length arg_typs = List.length param_typs && (* should be checked first before checking convertibility *)
      List.for_all2 FuncMap.is_implicitly_convertible arg_typs param_typs
    ) lib_funcs in
  (get_finfo matching_func).scope_s

let rec ufd_s : (id * typ) list -> func list -> stmt -> stmt
= fun lst lib_funcs stmt ->
  let lib_names = List.map fst lst in
  match stmt with
  | Call (lvop,Lv (MemberAccess (e,fname,fname_info,typ)),args,ethop,gasop,loc)
    when List.mem fname (List.map get_fname lib_funcs) (* e.g., (a+b).add(c) when using SafeMath *)
         && not (List.mem (to_string_exp e) lib_names) (* e.g., SafeMath.add (a,b) should not be changed. *) -> 
    let e_typ = get_type_exp e in
    let lst' = List.filter (fun (_,t) -> t = e_typ || t = Void) lst in (* "Void" is for the case of "using libname for *". *)
    let cand_lib_names = List.map fst lst' in
    (match List.length cand_lib_names with
     | 0 -> stmt (* no using for syntax *)
     | _ ->
       let arg_typs = List.map get_type_exp (e::args) in (* move the receiver to the first argument *)
       let lib_funcs' = List.filter (fun f -> List.mem (get_finfo f).scope_s cand_lib_names) lib_funcs in
       let lib_name = find_matching_lib_name lib_funcs' fname arg_typs in (* from libs, using fname and arg_typs, find corresponding library name *)
       let lib_typ = EType (Contract lib_name) in
       let lib_var = Lv (Var (lib_name, mk_vinfo ~typ:lib_typ ())) in
       Call (lvop,Lv (MemberAccess (lib_var,fname,fname_info,typ)),e::args,ethop,gasop,loc))
  | Call _ -> stmt 
  | Assign _ -> stmt
  | Decl _ -> stmt
  | Skip -> stmt
  | Seq (s1,s2) -> Seq (ufd_s lst lib_funcs s1, ufd_s lst lib_funcs s2)
  | If (e,s1,s2,i) -> If (e, ufd_s lst lib_funcs s1, ufd_s lst lib_funcs s2, i)
  | While (e,s) -> While (e, ufd_s lst lib_funcs s)
  | Break | Continue | Return _ | Throw 
  | Assume _ | Assert _ | Assembly _ | PlaceHolder -> stmt
  | Unchecked (blk,loc) ->
    let blk' = List.map (ufd_s lst lib_funcs) blk in
    Unchecked (blk',loc)

let ufd_f lst lib_funcs (fid, params, ret_params, stmt, finfo) = (fid, params, ret_params, ufd_s lst lib_funcs stmt, finfo)

let ufd_c pgm (cid, decls, structs, enums, funcs, cinfo) =
  let lib_names = List.map fst cinfo.lib_typ_lst in
  let libs = List.map (find_contract_id pgm) lib_names in
  let lib_funcs = List.fold_left (fun acc lib -> acc @ (get_funcs lib)) [] libs in
  (cid, decls, structs, enums, List.map (ufd_f cinfo.lib_typ_lst lib_funcs) funcs, cinfo)

let ufd_p contracts = List.map (ufd_c contracts) contracts
let ufd p = ufd_p p (* abbreviation for using for directives *) 

let prop_libs_c : contract list -> contract -> contract
= fun parents c -> (* propagete parents => c *)
  List.fold_left (fun acc parent ->
    let libs_parent = (get_cinfo parent).lib_typ_lst in
    let acc_info = get_cinfo acc in
    let libs' = BatSet.to_list (BatSet.union (BatSet.of_list libs_parent) (BatSet.of_list acc_info.lib_typ_lst)) in
    update_cinfo {acc_info with lib_typ_lst = libs'} acc 
  ) c parents

let prop_libs_p p =
  List.map (fun c ->
    let nids_of_parents = get_inherit_order c in
    let parents = List.tl (List.map (find_contract_nid p) nids_of_parents) in 
    prop_libs_c parents c 
  ) p

let propagate_libtyp pgm = prop_libs_p pgm

let replace_lib_calls pgm =
  pgm |> propagate_libtyp |> ufd

(**************************************)
(****** Add contract/lib name to ******)
(** function calls without prefixes ***)
(**************************************)

let rec add_cname_s : id -> var list -> stmt -> stmt
= fun cname func_typ_params stmt ->
  match stmt with
  | Seq (s1,s2) -> Seq (add_cname_s cname func_typ_params s1, add_cname_s cname func_typ_params s2)
  | If (e,s1,s2,i) -> If (e, add_cname_s cname func_typ_params s1, add_cname_s cname func_typ_params s2, i)
  | Call (lvop,Lv (Var (v,vinfo)),args,ethop,gasop,loc)
    when not (List.mem v built_in_funcs)
         && not (List.mem v init_funcs)
         && not (List.mem (v,vinfo.vtyp) func_typ_params) (* function pointer *)
    ->
    let prefix = Lv (Var (cname, mk_vinfo ~typ:(EType (Contract cname)) ())) in
    Call (lvop, Lv (MemberAccess (prefix, v, vinfo, vinfo.vtyp)), args, ethop, gasop, loc)
  | While (e,s) -> While (e, add_cname_s cname func_typ_params s)
  | Unchecked (lst, loc) ->
    let lst' = List.map (add_cname_s cname func_typ_params) lst in
    Unchecked (lst', loc)
  | _ -> stmt

let add_cname_f cname f =
  let func_typ_params = List.filter (fun v -> is_func_typ (snd v)) (get_param_vars f) in
  let old_stmt = get_body f in
  let new_stmt = add_cname_s cname func_typ_params old_stmt in
  update_body new_stmt f

let add_cname_c c =
  let cname = get_cname c in
  let old_funcs = get_funcs c in
  let new_funcs = List.map (add_cname_f cname) old_funcs in
  update_funcs new_funcs c 

let add_cname_p contracts =
  List.map add_cname_c contracts

let add_cname_fcalls p = add_cname_p p

(*****************************)
(*****************************)
(** Merge into one contract **)
(*****************************)
(*****************************)

let find_next_contracts : contract list -> id -> contract list
= fun lst target ->
  let names = List.map get_cname lst in
  let target_idx = match BatList.index_of target names with Some idx -> idx | None -> assert false in
  BatList.fold_lefti (fun acc i c ->
    if i<target_idx+1 then acc
    else acc@[c]
  ) [] lst

let add_func : func -> contract -> contract
= fun f ((cid,decls,structs,enums,funcs,cinfo) as contract) ->
  let b = List.exists (equal_sig f) funcs || (get_finfo f).is_constructor in
  (* Do not copy *)
  (* 1. if functions are constructors, and  *)
  (* 2. if functions with the same signatures are already exist in the contract *)
  if b then contract
  else
    let old_finfo = get_finfo f in
    let new_finfo = {old_finfo with scope = cinfo.numid; scope_s = cid} in
    let new_f = update_finfo new_finfo f in
    (cid, decls, structs, enums, funcs@[new_f], cinfo)

let add_func2 : contract -> contract -> contract
= fun _from _to ->
  let funcs = get_funcs _from in
  List.fold_left (fun acc f ->
    add_func f acc
  ) _to funcs

let equal_gdecl : state_var_decl -> state_var_decl -> bool 
= fun (id1,_,_) (id2,_,_) -> BatString.equal id1 id2

let add_decl : state_var_decl -> contract -> contract
= fun cand contract ->
  let (cid,decls,structs,enums,funcs,cinfo) = contract in
  (* let b = List.exists (equal_gdecl cand) decls in
    if b then contract
    else *) (cid, decls@[cand], structs, enums, funcs, cinfo)

let add_decl2 : contract -> contract -> contract
= fun _from _to ->
  let decls = get_decls _from in
  List.fold_left (fun acc d ->
    add_decl d acc 
  ) _to decls

let add_enum : contract -> contract -> contract
= fun _from _to ->
  (* Duplicated (i.e., already declared) enums by inheritance will be rejected by solc, so just copy enums. *)
  let enums1 = get_enums _from in
  let enums2 = get_enums _to in
  update_enums (enums1 @ enums2) _to

let add_struct : contract -> contract -> contract
= fun _from _to ->
  (* Similarly, duplicated (i.e., already declared) structures by inheritance will be rejected by solc, so just copy structures. *)
  let structs1 = get_structs _from in
  let structs2 = get_structs _to in
  update_structs (structs1 @ structs2) _to

let add_cnstr_mod_call' : func -> func -> func
= fun _from _to ->
  let _ = assert (is_constructor _from && is_constructor _to) in
  let modcall_from = List.rev (get_finfo _from).mod_list2 in
  let modcall_to = (get_finfo _to).mod_list2 in
  (* duplicated consturctor modifier invocation is error in solc >= 0.5.0,
   * but perform deduplication for compatibility with solc <= 0.4.26 *)
  let modcall_to' =
    List.fold_left (fun acc m ->
      let b = List.exists (fun (x,_,_) -> x = triple_fst m) acc in
      if b then acc
      else m::acc
    ) modcall_to modcall_from
  in
  let finfo_to = get_finfo _to in
  let finfo_to' = {finfo_to with mod_list2 = modcall_to'} in
  update_finfo finfo_to' _to

let add_cnstr_mod_call : contract -> contract -> contract
= fun _from _to ->
  let funcs = get_funcs _to in
  let funcs' =
     List.map (fun f ->
       if is_constructor f then add_cnstr_mod_call' (get_cnstr _from) (get_cnstr _to)
       else f
     ) funcs
  in
  update_funcs funcs' _to

let debug_abstract_contract parent c =
  if get_cname c = !Options.main_contract
     && parent |> get_cnstr |> get_params |> List.length <> 0 then
    (prerr_endline ("[WARNING] contract " ^ get_cname c ^ " may be abstract");
     prerr_endline ("- arguments for base contract " ^ get_cname parent ^ " constructor are not provided\n"))

let copy_c : contract list -> contract -> contract
= fun parents c ->
  let c' =
    List.fold_left (fun acc parent ->
      acc |> add_func2 parent |> add_decl2 parent |> add_enum parent
          |> add_struct parent |> add_cnstr_mod_call parent
    ) c parents
  in
  (* reorder constructor modifier invocations according to inheritance order *)
  let funcs = get_funcs c' in
  let funcs' =
    List.map (fun f ->
      if is_constructor f then
        let finfo = get_finfo f in
        let cnstr_mod_calls = finfo.mod_list2 in
        let cnstr_mod_calls' =
          (* recursive constructor calls are removed, as we iterate over parents. e.g., contract A { constructor (uint n) A (5) ... } *)
          List.fold_left (fun acc parent ->
            let matching = List.filter (fun (x,_,_) -> get_cname parent = x) cnstr_mod_calls in
            let _ = assert (List.length matching = 1 || List.length matching = 0) in
            if List.length matching = 1 then acc @ [List.hd matching]
            else
              let _ = debug_abstract_contract parent c in
              acc @ [(get_cname parent, [], dummy_loc)]
          ) [] (List.rev parents) in (* reverse to put parent's mod on the front. *)
        let finfo' = {finfo with mod_list2 = cnstr_mod_calls'} in
        update_finfo finfo' f
      else f
    ) funcs
  in
  update_funcs funcs' c'

let copy_p : pgm -> pgm
= fun p ->
  List.map (fun c ->
    let parents = List.tl (Global.get_full_base_contracts p c) in
    copy_c parents c
  ) p

let copy pgm = copy_p pgm

(*********************)
(*********************)
(** Replace 'super' **)
(*********************)
(*********************)

let rec rs_s : contract list -> id -> stmt -> stmt
= fun family cur_cname stmt ->
  match stmt with
  | Assign _ -> stmt
  | Decl _ -> stmt
  | Seq (s1,s2) -> Seq (rs_s family cur_cname s1, rs_s family cur_cname s2)
  | Call (lvop, Lv (MemberAccess (Lv (Var (x,xinfo)),id,id_info,typ)), args, ethop, gasop, loc)
    when BatString.equal x "super" ->
    let arg_typs = List.map get_type_exp args in
    let supers = find_next_contracts family cur_cname in
    let matched_parent =
      List.find (fun super ->
        let funcs = get_funcs super in
        List.exists (fun f ->
          let (id',typs') = get_fsig f in
          if BatString.equal id id' && List.length arg_typs = List.length typs' then
            List.for_all2 FuncMap.is_implicitly_convertible arg_typs typs'
          else false 
        ) funcs 
      ) supers in
    let matched_parent_name = get_cname matched_parent in
    Call (lvop, Lv (MemberAccess (Lv (Var (matched_parent_name,xinfo)),id,id_info,typ)), args, ethop, gasop, loc)
  | Call _ -> stmt
  | Skip -> stmt
  | If (e,s1,s2,i) -> If (e, rs_s family cur_cname s1, rs_s family cur_cname s2, i)
  | While (e,s) -> While (e, rs_s family cur_cname s)
  | _ -> stmt

let rs_f : contract list -> id -> func -> func
= fun final_inherit cur_cname f ->
  let old_body = get_body f in
  let new_body = rs_s final_inherit cur_cname old_body in
  update_body new_body f

let rs_c : contract list -> contract -> contract
= fun final_inherit c ->
  let cur_cname = get_cname c in 
  let old_funcs = get_funcs c in
  let new_funcs = List.map (rs_f final_inherit cur_cname) old_funcs in
  update_funcs new_funcs c 

let rs_p : pgm -> pgm
= fun p ->
  let main = get_main_contract p in
  let nids_of_parents = get_inherit_order main in
  let final_inherit = List.map (find_contract_nid p) nids_of_parents in
  let family_names = List.map get_cname final_inherit in
  List.fold_left (fun acc c ->
    if List.mem (get_cname c) family_names then
      let c' = rs_c final_inherit c in
      modify_contract c' acc
    else acc
  ) p p 

let replace_super pgm = rs_p pgm 

(**********************)
(**********************)
(** Generate getters **)
(**********************)
(**********************)

let get_public_state_vars : contract -> (id * vinfo) list
= fun c ->
  let decls = get_decls c in 
  let decls' = List.filter (fun (_,_,vinfo) -> vinfo.vvis = Public && (is_uintkind vinfo.vtyp || is_address vinfo.vtyp)) decls in
  List.map (fun (v,_,vinfo) -> (v,vinfo)) decls'

(* generate getter functions for public state variables *)
let add_getter_x : string -> int -> id * vinfo -> func
= fun cname cnumid (x,xinfo) ->
  let ret = (Translator.gen_param_name(), mk_vinfo ~typ:xinfo.vtyp ()) in
  let stmt = Return (Some (Lv (Var (x,xinfo))), mk_loc ~line:Query.code_public_getter ()) in
  let finfo = {is_constructor=false; is_payable=false; is_modifier=false;
               mod_list=[]; mod_list2=[];
               param_loc=dummy_loc; ret_param_loc=dummy_loc;
               fvis=External; mutability = View; fid=(-1); floc=dummy_loc; scope=cnumid; scope_s=cname; org_scope_s=cname; cfg=empty_cfg} in
  gen_func ~fname:x ~params:[] ~ret_params:[ret] ~stmt:stmt ~finfo:finfo

let add_getter_c : contract -> contract
= fun c ->
  let cname = get_cname c in
  let cnumid = (get_cinfo c).numid in
  let vars = get_public_state_vars c in
  List.fold_left (fun acc x ->
    let f = add_getter_x cname cnumid x in
    add_func f acc
  ) c vars

let add_getter_p p =
  List.fold_left (fun acc c ->
    let c' = add_getter_c c in
    let acc' = modify_contract c' acc in
    acc'
  ) p p

let add_getter pgm = add_getter_p pgm 

(******************************)
(******************************)
(** Inline Constructor Calls **)
(******************************)
(******************************)

let rec has_cnstr_calls_s : func list -> stmt -> bool
= fun cnstrs stmt ->
  match stmt with
  | Assign _ -> false
  | Seq (s1,s2) -> has_cnstr_calls_s cnstrs s1 || has_cnstr_calls_s cnstrs s2
  | Decl _ -> false
  | Call (None,Lv (Var (f,_)),_,_,_,_) when List.mem f (List.map get_fname cnstrs) -> true
  | Call _ -> false
  | Skip -> false
  | Assume _ -> false
  | While (_,s) -> has_cnstr_calls_s cnstrs s
  | If (_,s1,s2,_) -> has_cnstr_calls_s cnstrs s1 || has_cnstr_calls_s cnstrs s2
  | Continue | Break | Return _ | Throw | Assert _ | Assembly _ | PlaceHolder -> false
  | Unchecked (slst,_) -> List.exists (has_cnstr_calls_s cnstrs) slst

let has_cnstr_calls_f : func list -> func -> bool 
= fun cnstrs f ->
  if is_constructor f then
    has_cnstr_calls_s cnstrs (get_body f)
  else false

let has_cnstr_calls_c cnstrs c = List.exists (has_cnstr_calls_f cnstrs) (get_funcs c)
let has_cnstr_calls_p p = 
  let cnstrs = List.map get_cnstr p in 
  List.exists (has_cnstr_calls_c cnstrs) p
let has_cnstr_calls p = has_cnstr_calls_p p

let bind_params : loc -> param list -> exp list -> stmt
= fun loc params args ->
  try
    List.fold_left2 (fun acc (x,xinfo) arg -> 
      Seq (acc, Assign (Var (x,xinfo), arg, loc))
    ) Skip params args
  with Invalid_argument _ -> Skip

let rec replace_ph : stmt -> stmt -> stmt
= fun mod_body body ->
  match mod_body with
  | PlaceHolder -> body
  | Seq (s1,s2) -> Seq (replace_ph s1 body, replace_ph s2 body)
  | While (e,s) -> While (e, replace_ph s body)
  | If(e,s1,s2,i) -> If (e, replace_ph s1 body, replace_ph s2 body, i)
  | _ -> mod_body

let rec has_ph : stmt -> bool
= fun stmt ->
  match stmt with
  | PlaceHolder -> true
  | Seq (s1,s2) -> has_ph s1 || has_ph s2
  | While (_,s) -> has_ph s
  | If (_,s1,s2,_) -> has_ph s1 || has_ph s2
  | _ -> false

let assign_after_ph : stmt -> bool
= fun stmt ->
  match stmt with
  | Seq (Seq(s,PlaceHolder), Assign (lv,e,loc)) when not (has_ph s) -> true
  | _ -> false

let split_mod : stmt -> stmt * stmt
= fun stmt ->
  match stmt with
  | Seq ((Seq(s,PlaceHolder) as s1), (Assign (lv,e,loc) as s2)) when not (has_ph s) -> (s1,s2)
  | _ -> assert false

let rec insert : stmt -> stmt -> stmt
= fun stmt mod_post ->
  match stmt with
  | Seq (s1,s2) -> Seq (insert s1 mod_post, insert s2 mod_post)
  | While (e,s) -> While (e, insert s mod_post)
  | If(e,s1,s2,i) -> If (e, insert s1 mod_post, insert s2 mod_post, i)
  | Return (eop,_) -> Seq (mod_post, stmt)
  | _ -> stmt

let inline_mod_calls_f : func list -> func -> func
= fun funcs f ->
  let body = get_body f in
  let mods = List.rev (get_finfo f).mod_list in
  let body' =
    List.fold_left (fun acc m ->
      let mod_def = List.find (fun f -> get_fname f = triple_fst m) funcs in
      let binding = bind_params (triple_third m) (get_params mod_def) (triple_snd m) in
      let mod_body = get_body mod_def in
      if not (assign_after_ph mod_body) then Seq (binding, replace_ph mod_body acc)
      else
        let (mod_pre,mod_post) = split_mod mod_body in
        Seq (binding, insert (replace_ph mod_pre acc) mod_post)
    ) body mods
  in
  update_body body' f

let inline_cnstr_calls_f : func list -> func -> func
= fun cnstrs f ->
  if not (is_constructor f) then
    let _ = assert (List.length ((get_finfo f).mod_list2) = 0) in
    f
  else
    let body = get_body f in
    let mods = List.rev (get_finfo f).mod_list2 in
    let body' =
      List.fold_left (fun acc m ->
        let cnstr = List.find (fun f -> get_fname f = triple_fst m) cnstrs in
        let binding = bind_params (triple_third m) (get_params cnstr) (triple_snd m) in
        let cbody = get_body cnstr in
        Seq (Seq (binding, cbody), acc)
      ) body mods
    in
    update_body body' f

let inline_mods_c : func list -> contract -> contract
= fun cnstrs c ->
  let funcs = get_funcs c in
  let funcs' = List.map (inline_mod_calls_f funcs) funcs in
  let funcs'' = List.map (inline_cnstr_calls_f cnstrs) funcs' in
  update_funcs funcs'' c

let inline_mod_calls : pgm -> pgm
= fun p ->
  let cnstrs = List.map get_cnstr p in
  List.map (inline_mods_c cnstrs) p

(************************************)
(************************************)
(** return variable initialization **)
(************************************)
(************************************)

let add_retvar_init_f : func -> func
= fun f ->
  let ret_params = get_ret_params f in
  let new_stmt =
    List.fold_left (fun acc (x,xinfo) ->
      let s = Decl (Var (x,xinfo)) in
      if is_skip acc then s
      else Seq (acc,s)
    ) Skip ret_params in
  let body = get_body f in
  let new_body = if is_skip new_stmt then body else Seq (new_stmt,body) in
  update_body new_body f  

let add_retvar_init_c : contract -> contract
= fun c ->
  let funcs = get_funcs c in
  let funcs = List.map add_retvar_init_f funcs in
  update_funcs funcs c

let add_retvar_init_p : pgm -> pgm
= fun contracts ->
  List.map (fun c ->
   if BatString.equal (get_cinfo c).ckind "library" then c (* for optimization, do not introduce additional stmt for lib functions. *)
   else add_retvar_init_c c
  ) contracts 

let add_retvar_init : pgm -> pgm
= fun p -> add_retvar_init_p p


(*******************************)
(*******************************)
(*** return stmt at the exit ***)
(*******************************)
(*******************************)

let id = ref 0
let newid() = id:= !id+1; !id

let add_ret_s f s =
  try
    let lv = params_to_lv (get_ret_params f) in
    Seq (s, Return (Some (Lv lv), dummy_loc))
  with
    NoParameters -> Seq (s, Return (None, dummy_loc))

let add_ret_f f = update_body (add_ret_s f (get_body f)) f
let add_ret_c c = update_funcs (List.map (add_ret_f) (get_funcs c)) c
let add_ret pgm = List.map add_ret_c pgm

(***********************)
(***********************)
(** Variable Renaming **)
(***********************)
(***********************)

let do_not_rename (id,vinfo) =
  BatString.starts_with id tmpvar
  || BatString.starts_with id Translator.param_name (* ghost ret param names are already unique *)
  || vinfo.refid = -1 (* some built-in variables do not have reference id, thus we assign '-1' *)

let rec rename_lv cnames enums lv =
  match lv with
  | Var (id,vinfo) ->
    if do_not_rename (id,vinfo) then lv
    else Var (id ^ separator ^ string_of_int vinfo.refid, vinfo)
  | MemberAccess (Lv (Var (x,xt)),id,id_info,typ)
    when is_enum typ && List.mem x (List.map fst enums) ->
    let members = List.assoc x enums in
    let idx = remove_some (BatList.index_of id members) in
    MemberAccess (Lv (Var (x,xt)),id ^ "__idx" ^ string_of_int idx, id_info,typ)
  | MemberAccess (Lv (MemberAccess (e,fname,finfo,typ1)),"selector",sinfo,typ2) ->
    MemberAccess (Lv (MemberAccess (rename_e cnames enums e,fname,finfo,typ1)),"selector",sinfo,typ2)
  | MemberAccess (e,id,id_info,typ) ->
    let id' =
      if do_not_rename (id,id_info) then id
      else id ^ separator ^ string_of_int id_info.refid
    in
    MemberAccess (rename_e cnames enums e, id', id_info, typ)
  | IndexAccess (e,None,_) -> raise (Failure "rename_lv cnames enums1")
  | IndexAccess (e1,Some e2,typ) -> IndexAccess (rename_e cnames enums e1, Some (rename_e cnames enums e2), typ)
  | Tuple (eoplst,typ) ->
    let eoplst' = 
      List.map (fun eop ->
        match eop with
        | None -> None
        | Some e -> Some (rename_e cnames enums e)
      ) eoplst
    in
    Tuple (eoplst',typ)

and rename_e cnames enums exp =
  match exp with
  | Int _ | Real _ | Str _ -> exp
  | Lv lv ->
    if List.mem (to_string_lv lv) Lang.keyword_vars then Lv lv
    else Lv (rename_lv cnames enums lv)
  | Cast (typ,e) -> Cast (typ,rename_e cnames enums e)
  | BinOp (bop,e1,e2,einfo) -> BinOp (bop, rename_e cnames enums e1, rename_e cnames enums e2, einfo)
  | UnOp (uop,e,typ) -> UnOp (uop, rename_e cnames enums e, typ)
  | True | False | ETypeName _ -> exp
  | IndexRangeAccess (base,sop,fop,einfo) ->
    let base' = rename_lv cnames enums base in
    let sop' = match sop with None -> None | Some s -> Some (rename_e cnames enums s) in
    let fop' = match fop with None -> None | Some f -> Some (rename_e cnames enums f) in
    IndexRangeAccess (base',sop',fop',einfo)
  | TypeInfo _ -> exp

  | IncTemp (e,b,l) -> IncTemp (rename_e cnames enums e, b, l)
  | DecTemp (e,b,l) -> DecTemp (rename_e cnames enums e, b, l)
  | CallTemp (e,exps,ethop,gasop,einfo) ->
    let (e',exps',ethop',gasop') = rename_call_rhs cnames enums (e,exps,ethop,gasop) in
    CallTemp (e',exps',ethop',gasop',einfo)
  | CondTemp (e1,e2,e3,typ,loc) -> CondTemp (rename_e cnames enums e1, rename_e cnames enums e2, rename_e cnames enums e3, typ, loc)
  | AssignTemp (lv,e,loc) -> AssignTemp (rename_lv cnames enums lv, rename_e cnames enums e, loc)
  (* | IncTemp (e,b,l) | DecTemp (e,b,l) -> failwith "rename_e1"
  | CallTemp (_,_,_,_,einfo) -> failwith ("rename_e2: " ^ to_string_exp exp ^ "@" ^ string_of_int einfo.eloc.line)
  | CondTemp (_,_,_,_,loc) -> failwith ("rename_e3: " ^ to_string_exp exp ^ "@" ^ string_of_int loc.line)
  | AssignTemp (_,_,loc) -> failwith ("rename_e4: " ^ to_string_exp exp ^ "@" ^ string_of_int loc.line) *)

and rename_call_rhs cnames enums (e,exps,ethop,gasop) =
  let e' =
    (match e with
     | e when List.mem (to_string_exp e) built_in_funcs -> e
     | Lv (Var (fname,info)) -> e
     | Lv (MemberAccess (Lv (Var (prefix,_)), fname, fname_info, typ)) (* safemath.add(...) *)
       when List.mem prefix cnames || prefix = "super" -> e
     | Lv (MemberAccess (arg,fname,info,typ)) -> (* x.add(...), x[y].add(...) *)
       let arg' = rename_e cnames enums arg in
       Lv (MemberAccess (arg',fname,info,typ))
     | _ -> e) (* raise (Failure ("rename_s (preprocess.ml) : unexpected fname syntax - " ^ (to_string_stmt stmt))) *)
  in
  let exps' =
    let fname = to_string_exp e in
    if List.mem fname ["struct_init"; "struct_init2"; "contract_init"] then
      (List.hd exps)::(List.map (rename_e cnames enums) (List.tl exps)) (* Rule: the first arg is contract/struct name *)
    else List.map (rename_e cnames enums) exps
  in
  let ethop' = match ethop with None -> ethop | Some e -> Some (rename_e cnames enums e) in
  let gasop' = match gasop with None -> gasop | Some e -> Some (rename_e cnames enums e) in
  (e', exps', ethop', gasop')

let rec rename_s cnames enums stmt =
  match stmt with
  | Assign (lv,exp,loc) -> Assign (rename_lv cnames enums lv, rename_e cnames enums exp, loc)
  | Decl lv -> Decl (rename_lv cnames enums lv)
  | Seq (s1,s2) -> Seq (rename_s cnames enums s1, rename_s cnames enums s2)
  | Call (lvop, e, exps, ethop, gasop, loc) ->
    let lvop' =
      (match lvop with
       | None -> lvop
       | Some lv -> Some (rename_lv cnames enums lv)) in
    let (e',exps',ethop',gasop') = rename_call_rhs cnames enums (e,exps,ethop,gasop) in
    Call (lvop', e', exps', ethop', gasop', loc)
  | Skip -> Skip
  | If (e,s1,s2,i) -> If (rename_e cnames enums e, rename_s cnames enums s1, rename_s cnames enums s2, i)
  | While (e,s) -> While (rename_e cnames enums e, rename_s cnames enums s)
  | Break | Continue | Return (None,_) -> stmt
  | Return (Some e,loc) -> Return (Some (rename_e cnames enums e), loc)
  | Throw -> Throw
  | Assume (e,loc) -> Assume (rename_e cnames enums e, loc)
  | Assert (e,vtyp,loc) -> Assert (rename_e cnames enums e, vtyp, loc)
  | Assembly (lst,loc) ->
    Assembly (List.map (fun (x,refid) -> (x ^ separator ^ string_of_int refid, refid)) lst, loc)
  | PlaceHolder -> PlaceHolder
  | Unchecked (slst,loc) ->
    let slst' = List.map (rename_s cnames enums) slst in
    Unchecked (slst',loc)

let rename_param (id,vinfo) =
  if BatString.starts_with id Translator.param_name then (id,vinfo)
  else if is_func_typ vinfo.vtyp then (id,vinfo)
  else (id ^ separator ^ string_of_int vinfo.refid, vinfo)

let rename_f cnames enums (fid, params, ret_params, stmt, finfo) =
  (fid, List.map rename_param params, List.map rename_param ret_params, rename_s cnames enums stmt, finfo)

let rename_d decl =
  match decl with
  | (id,None,vinfo) -> (id ^ separator ^ string_of_int vinfo.refid, None, vinfo)
  | (id,Some e,vinfo) -> (id ^ separator ^ string_of_int vinfo.refid, Some e, vinfo)

let rename_st (sname, members) =
  let members' = List.map (fun (v,vinfo) -> (v ^ separator ^ string_of_int vinfo.refid, vinfo)) members in
  (sname, members')

let rename_c cnames (cid, decls, structs, enums, funcs, cinfo) =
  (cid, List.map rename_d decls, List.map rename_st structs, enums, List.map (rename_f cnames enums) funcs, cinfo)

let rename_p p =
  let cnames = get_cnames p in
  List.map (rename_c cnames) p

let rename pgm = rename_p pgm

let tuple_assign lv exp loc =
  match lv, exp with
  | Tuple (eops1, typ1), Lv (Tuple (eops2, _)) when List.length eops1 <> List.length eops2 -> begin
    match List.hd eops1 with
    | Some _ ->
      let (eops1', _) = list_fold (fun e (acc, acc_index) ->
        if acc_index = 0 then (acc@[None], acc_index)
        else (acc, acc_index - 1)
      ) eops2 (eops1, List.length eops1) in
      Assign (Tuple (eops1', typ1), exp, loc)
      
    | None ->
      let eops1' = List.tl eops1 in
      let (eops1'', _) = list_fold (fun e (acc, acc_index) ->
        if acc_index = 0 then (acc, acc_index)
        else (None::acc, acc_index - 1)
      ) eops2 (eops1', (List.length eops2) - (List.length eops1')) in
      Assign (Tuple (eops1'', typ1), exp, loc)
  end

    (* (bool success, ) = recipient.call.value(amountToWithdraw)("");
     * => (succcess, ) := Tmp
     * => success := Tmp *)
  | Tuple ([Some (Lv lv1);None],_), Lv lv2 -> Assign (lv1, Lv lv2, loc)
  | _ -> Assign (lv, exp, loc)

let rec tuple_s stmt =
  match stmt with
  | Assign (lv,exp,loc) -> tuple_assign lv exp loc
  | Decl (Tuple (eops,_)) ->
    List.fold_left (fun acc eop ->
      match eop with
      | None -> acc
      | Some (Lv lv) -> Seq (acc, Decl lv)
      | Some _ -> assert false
    ) Skip eops
  | Seq (s1,s2) -> Seq (tuple_s s1, tuple_s s2) 
  | If (e,s1,s2,i) -> If (e, tuple_s s1, tuple_s s2, i)
  | While (e,s) -> While (e, tuple_s s)
  | _ -> stmt

let tuple_f f = update_body (tuple_s (get_body f)) f
let tuple_c c = update_funcs (List.map tuple_f (get_funcs c)) c

let extend_tuple pgm = List.map tuple_c pgm

(*************)
(*************)
(** Casting **)
(*************)
(*************)

let rec cast_lv lv =
  match lv with
  | Var _ -> lv
  | MemberAccess (e,x,xinfo,typ) -> MemberAccess (cast_e e, x, xinfo, typ)
  | IndexAccess (e,None,typ) -> IndexAccess (cast_e e, None, typ)
  | IndexAccess (e1,Some e2,typ) ->
    let expected_idx_typ = domain_typ (get_type_exp e1) in
    let idx_typ = get_type_exp e2 in
    let e1' = cast_e e1 in
    let e2' = if expected_idx_typ = idx_typ then cast_e e2 else Cast (expected_idx_typ, cast_e e2) in
    IndexAccess (e1', Some e2', typ)
  | Tuple (eoplst,typ) ->
    let eoplst' = List.map (fun eop -> match eop with Some e -> Some (cast_e e) | None -> None) eoplst in
    Tuple (eoplst',typ)

and cast_e exp =
  match exp with
  | Int _ | Real _ | Str _ -> exp
  | Lv lv -> Lv (cast_lv lv)
  | Cast (typ,e) -> Cast (typ, cast_e e)
  | BinOp (bop,e1,e2,einfo) ->
    let t1 = get_type_exp e1 in
    let t2 = get_type_exp e2 in
    let ctyp = common_typ e1 e2 in
    let e1' = if t1 = ctyp then cast_e e1 else Cast (ctyp, cast_e e1) in
    let e2' = if t2 = ctyp then cast_e e2 else Cast (ctyp, cast_e e2) in
    BinOp (bop, e1', e2', einfo)
  | UnOp (uop,e,typ) -> UnOp (uop, cast_e e, typ)
  | True | False -> exp 
  | ETypeName _ -> exp
  | IndexRangeAccess (base,startop,finop,einfo) ->
    let f eop = match eop with Some e -> Some (cast_e e) | None -> None in
    IndexRangeAccess (cast_lv base, f startop, f finop, einfo)
  | TypeInfo _ -> exp
  | IncTemp _ | DecTemp _ | CallTemp _
  | CondTemp _ | AssignTemp _ -> failwith "cast_e" 

and cast_s stmt =
  match stmt with
  | Assign (lv,e,loc) ->
    let lv_typ = get_type_lv lv in
    let e_typ = get_type_exp e in
    let lv' = cast_lv lv in
    let e' = if lv_typ = e_typ then cast_e e else Cast (lv_typ, cast_e e) in
    Assign (lv', e', loc)
  | Decl lv -> stmt
  | Seq (s1,s2) -> Seq (cast_s s1, cast_s s2)
  | Call (lvop,e,elst,ethop,gasop,loc) ->
    let lvop' = match lvop with Some lv -> Some (cast_lv lv) | None -> None in
    let e' = cast_e e in
    let elst' = List.map cast_e elst in
    let ethop' = match ethop with Some e -> Some (cast_e e) | None -> None in
    let gasop' = match gasop with Some e -> Some (cast_e e) | None -> None in
    Call (lvop', e', elst', ethop', gasop', loc)
  | Skip -> stmt
  | If (e1,s1,s2,i) -> If (cast_e e1, cast_s s1, cast_s s2, i)
  | While (e,s) -> While (cast_e e, cast_s s)
  | Break | Continue -> stmt
  | Return _ | Throw -> stmt
  | Assume (e,loc) -> Assume (cast_e e, loc) 
  | Assert (e,vtyp,loc) -> Assert (cast_e e, vtyp, loc)
  | Assembly _ | PlaceHolder -> stmt
  | Unchecked (slst,loc) -> Unchecked (List.map cast_s slst, loc)

let cast_f f = update_body (cast_s (get_body f)) f
let cast_c c = update_funcs (List.map cast_f (get_funcs c)) c

let cast pgm = List.map cast_c pgm

(***************************************************************)
(**** Add guards for arithmetic operations (solv >= 0.8.0), ****)
(**** division (non-zero), array access (length > 0)        ****)
(***************************************************************)

(* Reference for division: https://github.com/Z3Prover/z3/issues/2843 *)
let rec add_io_dz_e ?(mode="all") exp =
  let _ = assert (mode = "all" || mode = "io" || mode = "dz") in
  match exp with
  | Int _ | Real _ | Str _ -> []
  | Lv lv -> add_io_dz_lv ~mode lv
  | Cast (_,e) -> add_io_dz_e ~mode e

  | BinOp (Add,e1,e2,einfo)
    when BatString.starts_with !Options.solc_ver "0.8"
         && (mode ="all" || mode = "io") ->
    (mk_ge (mk_add e1 e2) e1, einfo.eloc) :: ((add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2))

  | BinOp (Sub,e1,e2,einfo)
    when BatString.starts_with !Options.solc_ver "0.8"
         && (mode ="all" || mode = "io") ->
    (mk_ge e1 e2, einfo.eloc) :: ((add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2))

  | BinOp (Mul,e1,e2,einfo)
    when BatString.starts_with !Options.solc_ver "0.8"
         (* e.g., (1/100000) * (10**18) is not considered *)
         && (is_const_int (get_type_exp e1) || is_uintkind (get_type_exp e1) || is_sintkind (get_type_exp e1))
         && (is_const_int (get_type_exp e2) || is_uintkind (get_type_exp e2) || is_sintkind (get_type_exp e2))
         && (mode ="all" || mode = "io") ->
    let zero = mk_eq e1 (Int BatBig_int.zero) in
    let not_zero = mk_neq e1 (Int BatBig_int.zero) in
    let mul_div = mk_div exp e1 in
    (mk_or zero (mk_and not_zero (mk_eq mul_div e2)), einfo.eloc) :: ((add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2))

  | BinOp (Div,e1,e2,einfo) when (mode ="all" || mode = "dz") ->
    (mk_neq e2 (Int BatBig_int.zero), einfo.eloc) :: ((add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2))

  | BinOp (_,e1,e2,_) -> (add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2)
  | UnOp (_,e,_) -> add_io_dz_e ~mode e
  | True | False | ETypeName _ -> []
  | IndexRangeAccess (base,sop,fop,_) ->
    let lst1 = add_io_dz_lv ~mode base in
    let lst2 = match sop with Some s -> add_io_dz_e ~mode s | None -> [] in
    let lst3 = match fop with Some f -> add_io_dz_e ~mode f | None -> [] in
    lst1 @ lst2 @ lst3
  | TypeInfo _ -> []

  | IncTemp _ | DecTemp _ | CallTemp _
  | CondTemp _ | AssignTemp _ -> failwith "add_io_dz_e"

and add_io_dz_lv ?(mode="all") lv =
  let _ = assert (mode = "all" || mode = "io" || mode = "dz") in
  match lv with
  | Var _ -> []
  | MemberAccess (e,_,_,_) -> add_io_dz_e ~mode e
  | IndexAccess (e,None,t) -> add_io_dz_e ~mode e
  | IndexAccess (e1,Some e2,t) -> (add_io_dz_e ~mode e1) @ (add_io_dz_e ~mode e2)
  | Tuple (eops,_) ->
    List.fold_left (fun acc eop ->
      match eop with
      | None -> acc
      | Some e -> acc @ (add_io_dz_e ~mode e)
    ) [] eops

(* vaa: valid array access  *)
(* E.g., arr[i] => arr.length > i *)
let rec add_vaa_e exp =
  match exp with
  | Int _ | Real _ | Str _ -> []
  | Lv lv -> add_vaa_lv lv
  | Cast (_,e) -> add_vaa_e e
  | BinOp (_,e1,e2,_) -> (add_vaa_e e1) @ (add_vaa_e e2)
  | UnOp (_,e,_) -> add_vaa_e e
  | True | False | ETypeName _ | IndexRangeAccess _ | TypeInfo _ -> []
  | IncTemp _ | DecTemp _ | CallTemp _
  | CondTemp _ | AssignTemp _ -> failwith "add_vaa_e"

and add_vaa_lv lv =
  match lv with
  | Var _ -> []
  | MemberAccess (e,_,_,_) -> add_vaa_e e
  | IndexAccess (e,None,t) -> add_vaa_e e
  | IndexAccess (e1,Some e2,t) ->
    if is_array (get_type_exp e1) then
      ((mk_gt (mk_member_access e1 ("length", EType (UInt 256))) e2), dummy_loc)
      ::((add_vaa_e e1) @ (add_vaa_e e2))
    else
      (add_vaa_e e1) @ (add_vaa_e e2)
  | Tuple (eops,_) ->
    List.fold_left (fun acc eop ->
      match eop with
      | None -> acc
      | Some e -> acc @ (add_vaa_e e)
    ) [] eops

(* add assertions within unchecked blocks *)
let rec add_assert_unchecked stmt =
  let mode = "io" in
  let vultyp = "io" in
  match stmt with
  | Assign (lv,e,loc) ->
    let lst = (add_io_dz_lv ~mode lv) @ (add_io_dz_e ~mode e) in
    List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) stmt lst
  | Decl lv -> stmt
  | Seq (s1,s2) -> Seq (add_assert_unchecked s1, add_assert_unchecked s2)
  | Call (lvop,e,args,ethop,gasop,loc) ->
    let lvop_lst = match lvop with None -> [] | Some lv -> (add_io_dz_lv ~mode lv) in
    let e_lst = (add_io_dz_e ~mode e) in
    let args_lst = List.fold_left (fun acc e' -> acc @ (add_io_dz_e ~mode e')) [] args in
    let ethop_lst = match ethop with None -> [] | Some e -> (add_io_dz_e ~mode e) in
    let gasop_lst = match gasop with None -> [] | Some e -> (add_io_dz_e ~mode e) in
    let lst = lvop_lst @ e_lst @ args_lst @ ethop_lst @ gasop_lst in
    List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) stmt lst
  | Skip -> stmt

  | If (e,s1,s2,i) ->
    let lst = add_io_dz_e ~mode e in
    if List.length lst = 0 then
      If (e, add_assert_unchecked s1, add_assert_unchecked s2, i)
    else
      let s' = List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) Skip lst in
      Seq (s', If (e, add_assert_unchecked s1, add_assert_unchecked s2, i))

  | While (e,s) ->
    let lst = add_io_dz_e ~mode e in
    if List.length lst = 0 then
      While (e, add_assert_unchecked s)
    else
      let s' = List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) Skip lst in
      Seq (s', While (e, add_assert_unchecked s))

  | Break | Continue -> stmt
  | Return (None,_) -> stmt
  | Return (Some e,_) ->
    let lst = add_io_dz_e ~mode e in
    List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) stmt lst
  | Throw -> stmt
  | Assume (e,loc) ->
    let lst = add_io_dz_e ~mode e in
    List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) stmt lst
  | Assert (e,"default",loc) ->
    let lst = add_io_dz_e ~mode e in
    List.fold_left (fun acc (x,l) -> Seq (Assert (x, vultyp, l), acc)) stmt lst
  | Assert (e,_,loc) -> stmt (* automatically inserted assertion *)
  | Assembly _ | PlaceHolder -> stmt
  | Unchecked (slst,loc) -> assert false

let rec add_assume_s ?(mode="all") stmt =
  let _ = assert (mode = "all" || mode = "io" || mode = "dz") in
  match stmt with
  | Assign (lv,e,loc) ->
    let lst = (add_io_dz_lv ~mode lv) @ (add_io_dz_e ~mode e) @ (add_vaa_lv lv) @ (add_vaa_e e) in
    List.fold_left (fun acc (x,_) -> Seq (Assume (x, dummy_loc), acc)) stmt lst
  | Decl lv -> stmt
  | Seq (s1,s2) -> Seq (add_assume_s ~mode s1, add_assume_s ~mode s2)
  | Call (lvop,e,args,ethop,gasop,loc) ->
    let lvop_lst = match lvop with None -> [] | Some lv -> (add_io_dz_lv ~mode lv) @ (add_vaa_lv lv) in
    let e_lst = (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    let args_lst = List.fold_left (fun acc e' -> acc @ (add_io_dz_e ~mode e') @ (add_vaa_e e')) [] args in
    let ethop_lst = match ethop with None -> [] | Some e -> (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    let gasop_lst = match gasop with None -> [] | Some e -> (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    let lst = lvop_lst @ e_lst @ args_lst @ ethop_lst @ gasop_lst in
    List.fold_left (fun acc (x,_) -> Seq (Assume (x, dummy_loc), acc)) stmt lst
  | Skip -> stmt

  | If (e,s1,s2,i) ->
    let lst = (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    if List.length lst = 0 then (* just for readability of IL *)
      If (e, add_assume_s ~mode s1, add_assume_s ~mode s2, i)
    else
      let s' = List.fold_left (fun acc (x,_) -> Seq (acc, Assume (x, dummy_loc))) Skip lst in
      Seq (s', If (e, add_assume_s ~mode s1, add_assume_s ~mode s2, i))
      (* If (e, Seq (s', add_assume_s ~mode s1), Seq (s', add_assume_s ~mode s2), i) *)

  | While (e,s) ->
    let lst = (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    if List.length lst = 0 then (* just for readability of IL *)
      While (e, add_assume_s ~mode s)
    else
      let s' = List.fold_left (fun acc (x,_) -> Seq (acc, Assume (x, dummy_loc))) Skip lst in
      Seq (s' ,While (e, add_assume_s ~mode s))
      (* Seq (While (e, Seq (s', add_assume_s ~mode s)), s') *)

  | Break | Continue -> stmt
  | Return _ | Throw -> stmt
  | Assume (e,loc) ->
    let lst = (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    List.fold_left (fun acc (x,_) -> Seq (Assume (x, dummy_loc), acc)) stmt lst
  | Assert (e,"default",loc) ->
    let lst = (add_io_dz_e ~mode e) @ (add_vaa_e e) in
    List.fold_left (fun acc (x,_) -> Seq (Assume (x, dummy_loc), acc)) stmt lst
  | Assert (e,_,loc) -> stmt (* automatically inserted assertion *)
  | Assembly _ | PlaceHolder -> stmt
  | Unchecked (slst,loc) ->
    let slst = List.map (add_assume_s ~mode:"dz") slst in
    let slst = List.map add_assert_unchecked slst in
    List.fold_left (fun acc s ->
      if is_skip acc then s else Seq (acc,s)
    ) Skip slst

let add_assume_f f = update_body (add_assume_s (get_body f)) f
let add_assume_c c = update_funcs (List.map add_assume_f (get_funcs c)) c
let add_assume pgm = List.map add_assume_c pgm

(*****************************)
(**** Desugar struct_init ****)
(*****************************)

let rec fold_left2 lv loc acc members values =
  match members, values with
  | [], [] -> acc
  | [], h2::t2 -> invalid_arg "preprocess: desugar struct init"
  | h1::t1, [] ->
    if is_mapping (get_type_var2 h1) then
      let lv' = MemberAccess (Lv lv, fst h1, snd h1, get_type_var2 h1) in
      let stmt' = Decl lv' in
      let stmt'' = if is_skip acc then stmt' else Seq (acc,stmt') in
      fold_left2 lv loc stmt'' t1 []
    else invalid_arg "preprocess: desugar struct init"
  | h1::t1, h2::t2 ->
    if is_mapping (get_type_var2 h1) then
      let lv' = MemberAccess (Lv lv, fst h1, snd h1, get_type_var2 h1) in
      let stmt' = Decl lv' in
      let stmt'' = if is_skip acc then stmt' else Seq (acc,stmt') in
      fold_left2 lv loc stmt'' t1 (h2::t2)
    else
      let lv' = MemberAccess (Lv lv, fst h1, snd h1, get_type_var2 h1) in
      let stmt' = Assign (lv', h2, loc) in
      let stmt'' = if is_skip acc then stmt' else Seq (acc,stmt') in
      fold_left2 lv loc stmt'' t1 t2

let rec dsg cname smap stmt =
  match stmt with
  | Assign _ | Decl _ -> stmt
  | Seq (s1,s2) -> Seq (dsg cname smap s1, dsg cname smap s2)
  | Call (Some lv, Lv (Var ("struct_init",_)), args, ethop, gasop, loc) ->
    let (struct_exp, member_values) = (List.hd args, List.tl args) in
    (* Types of type-name-expressions are their type-names. E.g., typeOf (StructName) => ContractName.StructName *)
    (* see the implementation in frontend/translator.ml *)
    let members = StructMap.find (get_name_userdef (get_type_exp struct_exp)) smap in
    fold_left2 lv loc Skip members member_values
  | Call (Some lv, Lv (Var ("struct_init2",_)), args,ethop, gasop, loc) ->
    let (args1, args2) = BatList.split_at ((List.length args / 2) + 1) args in
    let (struct_exp, member_names, member_values) = (List.hd args1, List.tl args1, args2) in
    let org_members = StructMap.find (get_name_userdef (get_type_exp struct_exp)) smap in
    let find_matching_member mname member_lst = List.find (fun (name',_) -> BatString.starts_with name' (to_string_exp mname)) member_lst in
    let members = List.map (fun name -> find_matching_member name org_members) member_names in
    fold_left2 lv loc Skip members member_values
  | Call _ -> stmt
  | Skip -> stmt
  | If (e,s1,s2,i) -> If (e, dsg cname smap s1, dsg cname smap s2, i)
  | While (e,s) -> While (e, dsg cname smap s)
  | Break | Continue -> stmt
  | Return _ | Throw -> stmt
  | Assume _ | Assert _ | Assembly _ | PlaceHolder -> stmt
  | Unchecked (lst,loc) ->
    let lst' = List.map (dsg cname smap) lst in
    List.fold_left (fun acc s ->
      if is_skip acc then s else Seq (acc,s)
    ) Skip lst'

let desugar_struct_f cname smap f = update_body (dsg cname smap (get_body f)) f

let desugar_struct_c smap c =
  let cname = get_cname c in
  update_funcs (List.map (desugar_struct_f cname smap) (get_funcs c)) c

let desugar_struct pgm =
  let smap = StructMap.mk_smap pgm in
  List.map (desugar_struct_c smap) pgm

let run : pgm -> pgm
= fun p ->
  let p = copy p in
  let p = inline_mod_calls p in (* after 'copy' *)
  let p = move_decl_to_cnstr p in (* after 'copy' *)
  let p = replace_tmpexp p in (* after 'inline_mod_calls'; due to function call expressions (callTemp) as modifier arguments *)

  let p = normalize p in
  let p = rmskip p in
  let p = replace_lib_calls p in
  let p = add_cname_fcalls p in (* after 'copy' *)
  let p = add_getter p in
  let p = rmskip p in
  let p = replace_super p in
  let p = rmskip p in
  let p = rename p in
  let p = add_retvar_init p in
  (* let p = add_ret p in *)
  let p = extend_tuple p in
  let p = add_assume p in
  let p = desugar_struct p in
  let p = rmskip p in
  p
