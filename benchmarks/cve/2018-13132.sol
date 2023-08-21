pragma solidity ^0.4.18;


/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}


/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/179
 */
contract ERC20Basic {
  uint256 public totalSupply;
  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
}


/**
 * @title Basic token
 * @dev Basic version of StandardToken, with no allowances.
 */
contract BasicToken is ERC20Basic {
  using SafeMath for uint256;

  mapping(address => uint256) balances;

  /**
  * @dev transfer token for a specified address
  * @param _to The address to transfer to.
  * @param _value The amount to be transferred.
  */
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    // SafeMath.sub will throw if there is not enough balance.
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    Transfer(msg.sender, _to, _value);
    return true;
  }

  /**
  * @dev Gets the balance of the specified address.
  * @param _owner The address to query the the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }

}



/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 is ERC20Basic {
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);
  event Approval(address indexed owner, address indexed spender, uint256 value);
}



/**
 * @title Standard ERC20 token
 *
 * @dev Implementation of the basic standard token.
 * @dev https://github.com/ethereum/EIPs/issues/20
 * @dev Based on code by FirstBlood: https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 */
contract StandardToken is ERC20, BasicToken {

  mapping (address => mapping (address => uint256)) internal allowed;


  /**
   * @dev Transfer tokens from one address to another
   * @param _from address The address which you want to send tokens from
   * @param _to address The address which you want to transfer to
   * @param _value uint256 the amount of tokens to be transferred
   */
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    Transfer(_from, _to, _value);
    return true;
  }

  /**
   * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
   *
   * Beware that changing an allowance with this method brings the risk that someone may use both the old
   * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
   * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
   * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
   * @param _spender The address which will spend the funds.
   * @param _value The amount of tokens to be spent.
   */
  function approve(address _spender, uint256 _value) public returns (bool) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  /**
   * @dev Function to check the amount of tokens that an owner allowed to a spender.
   * @param _owner address The address which owns the funds.
   * @param _spender address The address which will spend the funds.
   * @return A uint256 specifying the amount of tokens still available for the spender.
   */
  function allowance(address _owner, address _spender) public view returns (uint256) {
    return allowed[_owner][_spender];
  }

  /**
   * approve should be called when allowed[_spender] == 0. To increment
   * allowed value is better to use this function to avoid 2 calls (and wait until
   * the first transaction is mined)
   * From MonolithDAO Token.sol
   */
  function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
    allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

  function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
    uint oldValue = allowed[msg.sender][_spender];
    if (_subtractedValue > oldValue) {
      allowed[msg.sender][_spender] = 0;
    } else {
      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
    }
    Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

}


// Migration Agent interface
contract MigrationAgent {
  function migrateFrom(address _from, uint _value) public;
}

/**
 * @title Spade Token
 */
contract SPXToken is StandardToken {

  string public constant name = "SP8DE Token";
  string public constant symbol = "SPX";
  uint8 public constant decimals = 18;
  address public ico;
  
  bool public isFrozen = true;  
  uint public constant TOKEN_LIMIT = 8888888888 * (1e18);

  // Token migration variables
  address public migrationMaster;
  address public migrationAgent;
  uint public totalMigrated;

  event Migrate(address indexed _from, address indexed _to, uint _value);
  
  // Constructor
  function SPXToken(address _ico, address _migrationMaster) public {
    require(_ico != 0);
    ico = _ico;
    migrationMaster = _migrationMaster;
  }

  // Create tokens
  function mint(address holder, uint value) public {
    require(msg.sender == ico);
    require(value > 0);
    require(totalSupply + value <= TOKEN_LIMIT); // <IO_VUL>

    balances[holder] += value; // <IO_VUL>
    totalSupply += value; // <IO_VUL>
    Transfer(0x0, holder, value);
  }

  // Allow token transfer.
  function unfreeze() public {
      require(msg.sender == ico);
      isFrozen = false;
  }

  // ERC20 functions
  // =========================
  function transfer(address _to, uint _value) public returns (bool) {
    require(_to != address(0));
    require(!isFrozen);
    return super.transfer(_to, _value);
  }

  function transferFrom(address _from, address _to, uint _value) public returns (bool) {
    require(!isFrozen);
    return super.transferFrom(_from, _to, _value);
  }

  function approve(address _spender, uint _value) public returns (bool) {
    require(!isFrozen);
    return super.approve(_spender, _value);
  }

  // Token migration
  function migrate(uint value) external {
    require(migrationAgent != 0);
    require(value > 0);
    require(value <= balances[msg.sender]);

    balances[msg.sender] -= value;
    totalSupply -= value;
    totalMigrated += value;
    MigrationAgent(migrationAgent).migrateFrom(msg.sender, value);
    Migrate(msg.sender, migrationAgent, value);
  }

  // Set address of migration contract
  function setMigrationAgent(address _agent) external {
    require(migrationAgent == 0);
    require(msg.sender == migrationMaster);
    migrationAgent = _agent;
  }

  function setMigrationMaster(address _master) external {
    require(msg.sender == migrationMaster);
    require(_master != 0);
    migrationMaster = _master;
  }
}

/**
 * @title Spade SpadeIco
 */
contract SpadeIco {
  
  uint public constant TOKENS_FOR_SALE = 3655555558 * 1e18;
  uint public constant TOKENS_FOUNDATION = 1777777778 * 1e18;
  
  uint tokensSold = 0;
  
  // Ico token
  SPXToken public token;
  address public team;
  address public icoAgent;
  address public migrationMaster;
  // Modifiers
  modifier teamOnly {require(msg.sender == team); _;}
  modifier icoAgentOnly {require(msg.sender == icoAgent); _;}
  
  bool public isPaused = false;
  enum IcoState { Created, IcoStarted, IcoFinished }
  IcoState public icoState = IcoState.Created;

  event IcoStarted();
  event IcoFinished();
  event IcoPaused();
  event IcoResumed();
  event TokenBuy(address indexed buyer, uint256 tokens, uint256 factor, string tx);
  event TokenBuyPresale(address indexed buyer, uint256 tokens, uint256 factor, string tx);
  event TokenWin(address indexed buyer, uint256 tokens, uint256 jackpot);

  function SpadeIco(address _team, address _icoAgent, address _migrationMaster) public {
    require(_team != address(0) && _icoAgent != address(0) && _migrationMaster != address(0));  
    migrationMaster = _migrationMaster;
    team = _team;
    icoAgent = _icoAgent;
    token = new SPXToken(this, migrationMaster);
  }

  function startIco() external teamOnly {
    require(icoState == IcoState.Created);
    icoState = IcoState.IcoStarted;
    IcoStarted();
  }

  function finishIco(address foundation, address other) external teamOnly {
    require(foundation != address(0));
    require(other != address(0));

    require(icoState == IcoState.IcoStarted);
    icoState = IcoState.IcoFinished;
    
    uint256 amountWithFoundation = SafeMath.add(token.totalSupply(), TOKENS_FOUNDATION);
    if (amountWithFoundation > token.TOKEN_LIMIT()) {
      uint256 foundationToMint = token.TOKEN_LIMIT() - token.totalSupply();
      if (foundationToMint > 0) {
        token.mint(foundation, foundationToMint);
      }
    } else {
        token.mint(foundation, TOKENS_FOUNDATION);

        uint mintedTokens = token.totalSupply();
    
        uint remaining = token.TOKEN_LIMIT() - mintedTokens;
        if (remaining > 0) {
          token.mint(other, remaining);
        }
    }

    token.unfreeze();
    IcoFinished();
  }

  function pauseIco() external teamOnly {
    require(!isPaused);
    require(icoState == IcoState.IcoStarted);
    isPaused = true;
    IcoPaused();
  }

  function resumeIco() external teamOnly {
    require(isPaused);
    require(icoState == IcoState.IcoStarted);
    isPaused = false;
    IcoResumed();
  }

  function convertPresaleTokens(address buyer, uint256 tokens, uint256 factor, string txHash) external icoAgentOnly returns (uint) {
    require(buyer != address(0));
    require(tokens > 0);
    require(validState());

    uint256 tokensToSell = SafeMath.add(tokensSold, tokens);
    require(tokensToSell <= TOKENS_FOR_SALE);
    tokensSold = tokensToSell;            

    token.mint(buyer, tokens);
    TokenBuyPresale(buyer, tokens, factor, txHash);
  }

  function creditJackpotTokens(address buyer, uint256 tokens, uint256 jackpot) external icoAgentOnly returns (uint) {
    require(buyer != address(0));
    require(tokens > 0);
    require(validState());

    token.mint(buyer, tokens);
    TokenWin(buyer, tokens, jackpot);
  }

  function buyTokens(address buyer, uint256 tokens, uint256 factor, string txHash) external icoAgentOnly returns (uint) {
    require(buyer != address(0));
    require(tokens > 0);
    require(validState());

    uint256 tokensToSell = SafeMath.add(tokensSold, tokens);
    require(tokensToSell <= TOKENS_FOR_SALE);
    tokensSold = tokensToSell;            

    token.mint(buyer, tokens);
    TokenBuy(buyer, tokens, factor, txHash);
  }

  function validState() internal view returns (bool) {
    return icoState == IcoState.IcoStarted && !isPaused;
  }
}