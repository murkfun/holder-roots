// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IVerifier} from "./verifiers/BatchVerifier.sol";

/// @dev What MurkFunHolderRoots reads of the SPACE ID Agent ID registry (HandleRegistry on BSC, verified source;
///   test/utils/HandleRegistry.sol is a copy).
interface IHandleRegistry {
  function handleOf(address owner) external view returns (string memory);
  function signer() external view returns (address);
}

/// @title MurkFunHolderRoots
/// @notice The holder set: an append-only Poseidon2 Merkle tree of the SPACE ID Agent ID holders on BSC that
///   claimed their Agent ID through the user path (`HandleRegistry.register`, signed by SPACE ID's backend for a
///   Binance Agentic Wallet), kept by a bonded operator and checkable by anyone (docs/SIGNED_ORDERS.md, "Holder set").
///   No holder ever sends a transaction: the operator copies the public `Registered` events into batches.
///   Addresses minted by the registry owner (`adminRegister`, any address) are not part of the set.
///
///   Tree: depth 26 = 2^16 batch slots of 2^10 leaves. Batch `id` fills slot `id` (zero-padded), leaf(A) = H(A). The
///   Agent ID is soulbound (no transfers, no burns), so a holder stays a holder.
///
///   - Roles: the owner (Ownable2Step, transferable in two steps) sets the operator (`setOperator`) and the adjustable
///     parameters (`setParams`). Only the operator posts batches; nobody else can.
///   - `postBatch` (the operator only): appends 1..1024 addresses, strictly increasing (so none is 0 and none
///     repeats), as the next batch. A batch proof (circuits/batch) shows newRoot = append(currentRoot, addrs) with
///     every address as a public input, so the root is bound to exactly the published list (also emitted in `Batch`).
///     There is no on-chain interval between batches (the cadence is the operator's, off-chain).
///   - Challenge window: a batch's root is usable from its `usableFrom` (fixed at posting: postedAt + CHALLENGE_PERIOD,
///     never before the previous live batch's), and not while an origin dispute against it or an earlier batch is
///     unanswered (`heldFrom`): an admin-minted entry disputed in time is never usable.
///   - Fraud proofs: `challenge` (at ANY time, also after the window) shows one listed address holds no Agent ID: the
///     contract checks it on the spot, and as the Agent ID is soulbound it never succeeds against a holder.
///     `disputeOrigin` (only inside the batch's challenge window) + `resolveOrigin` show one listed address has no
///     SPACE ID `register` signature: anyone can answer a dispute with that signature (`defendOrigin`); one open
///     dispute per address and batch, and an address whose signature was verified once is never disputable again.
///     A dispute holds its batch (and every later one) until it is answered, so an unanswered dispute only ever
///     drops roots that never became usable. A successful fraud proof drops the batch and every later one (so the
///     bad leaf is in no usable root any more), slashes the whole bond to the challenger and restores the
///     forced-inclusion queue the dropped batches consumed. Both are commit-reveal (`commit` one block before), so a
///     copied transaction does not earn the reward.
///   - Forced inclusion (free): `enqueue(addr, deadline, sig)` (anyone, with the address's `register` signature) puts
///     `addr` in a queue that the operator's next batches must include once it is QUEUE_GRACE old (a batch built just
///     before an enqueue landed stays valid, so a front-run enqueue can not make it revert). Each address can be
///     enqueued at most once, ever (`enqueued`), so re-enqueueing included holders is bounded by the number of
///     holders; an enqueued address that is already in the tree is simply included again (a duplicate leaf is
///     harmless).
///   - Root history: a root stays valid until ROOT_HISTORY newer batches have been accepted.
///   - Bond: per depositor. Only a depositor withdraws its own deposit, and only while no batch is in its window and
///     no dispute is open. A slash takes every deposit.
///   - Adjustable parameters (`setParams`, the owner, effective at once): CHALLENGE_PERIOD (>= MIN_CHALLENGE_PERIOD),
///     ROOT_HISTORY (>= 1), MIN_BOND, DISPUTE_DEPOSIT. A posted batch keeps the window it was posted with and an open
///     dispute keeps its answer deadline and deposit, so no change makes a posted root usable earlier than
///     postedAt + MIN_CHALLENGE_PERIOD or cuts an open dispute's answer window below MIN_CHALLENGE_PERIOD.
/// @dev The operator can stall (stop posting: the forced-inclusion queue then waits too, as nobody else can post;
///   the owner's remedy is `setOperator`) but can not add a non-holder or an admin-minted address (fraud proofs, any
///   time), hide a holder while it posts (the queue) or add anything not in the published list (the batch proof).
///   `scripts/holders-audit.mjs` diffs the batches with the registry's events.
///   Trust assumption: SPACE ID signs `register` only for Binance Agentic Wallets, whose signer is deterministic
///   (one seed signature per wallet, so one pseudonym per token). The known signers are the registry's current
///   `signer()`, those passed at deployment (from the registry's `SignerChanged` history, publicly checkable) and
///   every signer that was current when anyone called `recordSigner`, `postBatch`, `enqueue`,
///   `disputeOrigin` or `defendOrigin` (each records the current signer; the sync bot also calls `recordSigner` on
///   every `SignerChanged`).
/// @custom:website https://murk.fun
/// @custom:x https://x.com/murkfun
contract MurkFunHolderRoots is Ownable2Step {
  uint256 internal constant FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
  uint256 public constant BATCH_SIZE = 1024;
  uint256 public constant MAX_BATCHES = 1 << 16;
  /// @notice A queue entry younger than this need not be in a batch yet (the operator reads the queue, proves, then
  ///   posts: an entry enqueued meanwhile must not make that batch revert). Older entries must be included.
  uint256 public constant QUEUE_GRACE = 1 hours;
  /// @notice Floor of CHALLENGE_PERIOD (constructor and `setParams`).
  uint256 public constant MIN_CHALLENGE_PERIOD = 10 minutes;
  /// @notice `heldFrom` when no batch is held.
  uint256 internal constant NONE = type(uint256).max;
  /// @notice Root of the empty tree (ZEROS[26], js/zk/core.mjs). Hard-coded: a different start could hide leaves.
  uint256 public constant EMPTY_ROOT = 0x1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9;
  /// @notice HandleRegistry's EIP-712 type of the backend's registration signature.
  bytes32 public constant REGISTER_TYPEHASH = keccak256("Register(string handle,address owner,uint256 deadline)");

  IERC721 public immutable AGENT_NFT;
  IVerifier public immutable BATCH_VERIFIER;
  /// @notice EIP-712 domain separator of the registry (HandleRegistry, version 1, this chain).
  bytes32 public immutable REGISTRY_DOMAIN;

  struct BatchInfo {
    uint256 root; // tree root after this batch
    bytes32 listHash; // keccak256(abi.encodePacked(addrs))
    uint64 postedAt;
    uint64 queueStart; // queueHead before this batch consumed the queue
    uint32 holds; // unanswered origin disputes of this batch (opened inside its challenge window)
    uint32 serial; // 1 + the number of batches posted before this one (tells a re-posted slot from the batch it replaced)
    uint64 usableFrom; // end of the challenge window, fixed at posting (see postBatch)
  }

  struct Deposit {
    uint192 amount;
    uint64 epoch; // deposits of an earlier epoch were slashed
  }

  struct Dispute {
    address disputer;
    uint64 openedAt;
    uint32 batchId;
    address addr;
    uint64 postedAt; // of the disputed batch (a re-posted slot is another batch)
    uint16 index;
    bool holds; // always true (disputes open only inside the batch's challenge window): holds it until answered
    bytes32 listHash;
    uint32 serial; // of the disputed batch
    uint64 answerBy; // openedAt + CHALLENGE_PERIOD at opening: `resolveOrigin` from then on
    uint96 deposit; // DISPUTE_DEPOSIT at opening: what the winner of the dispute gets back
  }

  // adjustable parameters (`setParams`); upper-case getters as when they were immutable
  /// @notice Seconds a newly posted batch waits before its root becomes usable; also the time to answer a newly
  ///   opened origin dispute. Each batch / dispute keeps the value it was posted / opened with.
  // forge-lint: disable-next-line(mixed-case-variable)
  uint256 public CHALLENGE_PERIOD;
  /// @notice A root stays valid until this many newer batches are accepted (live value: a change applies to every
  ///   root at once; at least 1, so the latest accepted root always stays valid).
  // forge-lint: disable-next-line(mixed-case-variable)
  uint256 public ROOT_HISTORY;
  /// @notice postBatch needs at least this bond.
  // forge-lint: disable-next-line(mixed-case-variable)
  uint256 public MIN_BOND;
  /// @notice Deposit of a newly opened `disputeOrigin`: back to the disputer if it wins, to the defender otherwise.
  // forge-lint: disable-next-line(mixed-case-variable)
  uint256 public DISPUTE_DEPOSIT;

  /// @notice The only address that can post batches; set by the owner (`setOperator`).
  address public operator;
  /// @notice Bumped by every slash: older deposits are void.
  uint64 public slashEpoch;
  /// @notice Sum of the current deposits.
  uint256 public bond;

  /// @notice Live batches are 0 .. batchCount - 1 (a successful challenge truncates).
  uint256 public batchCount;
  /// @notice Batches posted so far (re-posted slots included).
  uint32 public posted;
  /// @notice Lowest live batch held by an unanswered in-window origin dispute (NONE = none): its root and every
  ///   later one are not usable (not "accepted") until the disputes are answered or resolved.
  uint256 public heldFrom = NONE;
  mapping(uint256 id => BatchInfo) public batches;
  /// @notice 1 + the batch that produced `root` (stale after a drop: always compared with batches[id].root).
  mapping(uint256 root => uint256) internal _rootBatch;

  /// @notice Forced-inclusion queue.
  mapping(uint256 => address) public queue;
  uint256 public queueHead;
  uint256 public queueTail;
  /// @notice Whether the address was ever enqueued (at most once per address).
  mapping(address => bool) public enqueued;
  /// @notice When each queue position was enqueued.
  mapping(uint256 => uint64) public queuedTime;

  mapping(address => Deposit) internal _deposits;
  /// @notice Registration signers accepted by `defendOrigin` / `enqueue` (besides the registry's current one).
  mapping(address => bool) public knownSigner;
  /// @notice Block of a challenge commitment (see commitHash).
  mapping(bytes32 => uint256) public commits;
  mapping(uint256 => Dispute) public disputes;
  uint256 public disputeCount;
  /// @notice Addresses whose `register` signature was verified (`defendOrigin`, `enqueue`): their origin is proven for
  ///   good (the Agent ID is soulbound and a known signer stays known), so they can not be disputed again.
  mapping(address => bool) public provenOrigin;
  /// @notice Whether an open dispute exists for address `addr` in the batch posted as `serial` (key
  ///   keccak256(serial, addr)): one at a time, so disputes can not pile up holds on one entry.
  mapping(bytes32 => bool) public disputeOpen;
  uint256 public openDisputes;

  event Batch(
    uint256 indexed id,
    uint256 fromRoot,
    uint256 newRoot,
    uint256 subtreeRoot,
    address[] addrs,
    uint64 fromBlock,
    uint64 toBlock
  );
  event Challenged(
    uint256 indexed id, uint256 index, address addr, address challenger, uint256 reward, uint256 dropped
  );
  event Committed(bytes32 indexed commitment, address indexed from);
  event OriginDisputed(uint256 indexed dispute, uint256 indexed id, uint256 index, address addr, address disputer);
  event OriginDefended(uint256 indexed dispute, address addr, address signer, address defender);
  event DisputeVoid(uint256 indexed dispute);
  event Enqueued(uint256 indexed position, address addr);
  event SignerRecorded(address signer);
  event Bonded(address from, uint256 amount);
  event BondWithdrawn(address indexed from, address to, uint256 amount);
  event OperatorTransferred(address indexed previous, address indexed operator);
  event ParamsSet(uint256 challengePeriod, uint256 rootHistory, uint256 minBond, uint256 disputeDeposit);

  error NotOperator();
  error BadBatch();
  error NotSorted();
  error BondTooLow();
  error QueueNotConsumed(uint256 position);
  error InvalidProof();
  error NotLive();
  error WrongList();
  error IsHolder();
  error NotHolder();
  error NotRegistered();
  error AlreadyEnqueued();
  error NoCommit();
  error WrongDeposit();
  error Pending();
  error NotOpen();
  error TransferFailed();
  error BadParams();
  error ZeroOperator();
  error OriginProven();
  error AlreadyDisputed();
  error WindowClosed();

  modifier onlyOperator() {
    if (msg.sender != operator) revert NotOperator();
    _;
  }

  /// @notice The adjustable parameters (constructor, `setParams`): CHALLENGE_PERIOD, ROOT_HISTORY, MIN_BOND,
  ///   DISPUTE_DEPOSIT.
  struct Config {
    uint256 challengePeriod;
    uint256 rootHistory;
    uint256 minBond;
    uint256 disputeDeposit;
  }

  /// @param owner_ The owner (Ownable2Step): sets the operator and the parameters.
  /// @param signers The registry's registration signers before this deployment (its `SignerChanged` events); the
  ///   current `signer()` is always accepted.
  constructor(
    IERC721 agentNft,
    IVerifier batchVerifier,
    address owner_,
    address operator_,
    Config memory c,
    address[] memory signers
  ) payable Ownable(owner_) {
    AGENT_NFT = agentNft;
    BATCH_VERIFIER = batchVerifier;
    REGISTRY_DOMAIN = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256("HandleRegistry"),
        keccak256("1"),
        block.chainid,
        address(agentNft)
      )
    );
    for (uint256 i; i < signers.length; i++) {
      knownSigner[signers[i]] = true;
      emit SignerRecorded(signers[i]);
    }
    _setParams(c);
    _setOperator(operator_);
    if (msg.value != 0) _bond();
  }

  // =================================================================== owner

  /// @notice Set the adjustable parameters (effective at once). Floors: challengePeriod >= MIN_CHALLENGE_PERIOD,
  ///   rootHistory >= 1; overflow guards: challengePeriod <= 2^32 - 1, rootHistory <= MAX_BATCHES, disputeDeposit
  ///   <= 2^96 - 1. Batches already posted keep their `usableFrom` and open disputes their `answerBy` and deposit,
  ///   so a lower CHALLENGE_PERIOD only shortens the windows of later batches and disputes (never below the floor)
  ///   and a higher one never reopens an accepted root. ROOT_HISTORY applies to every root at once; MIN_BOND from
  ///   the next `postBatch`.
  function setParams(Config calldata c) external onlyOwner {
    _setParams(c);
  }

  /// @notice Set the operator (the only batch poster) directly: the previous one can not post from this
  ///   transaction on. Deposits stay with their depositors.
  function setOperator(address next) external onlyOwner {
    _setOperator(next);
  }

  function _setParams(Config memory c) internal {
    if (
      c.challengePeriod < MIN_CHALLENGE_PERIOD || c.challengePeriod > type(uint32).max || c.rootHistory == 0
        || c.rootHistory > MAX_BATCHES || c.disputeDeposit > type(uint96).max
    ) revert BadParams();
    CHALLENGE_PERIOD = c.challengePeriod;
    ROOT_HISTORY = c.rootHistory;
    MIN_BOND = c.minBond;
    DISPUTE_DEPOSIT = c.disputeDeposit;
    emit ParamsSet(c.challengePeriod, c.rootHistory, c.minBond, c.disputeDeposit);
  }

  function _setOperator(address next) internal {
    if (next == address(0)) revert ZeroOperator();
    emit OperatorTransferred(operator, next);
    operator = next;
  }

  // =================================================================== operator

  /// @notice Append `addrs` (1..1024, strictly increasing) as batch `batchCount` (the operator only, with at least
  ///   MIN_BOND bonded). `subtreeRoot` is the batch's own 1024-leaf root (lets clients rebuild paths without hashing
  ///   every batch); `fromBlock` / `toBlock` record the log range scanned (informational: the audit uses its own
  ///   head). The batch must include the live queue entries in queue order, as many as fit (see _consumeQueue). Its
  ///   root is usable from max(now + CHALLENGE_PERIOD, the previous live batch's `usableFrom`): roots become usable
  ///   in order, and never before postedAt + MIN_CHALLENGE_PERIOD.
  /// @param proof circuits/batch proof of newRoot = append(currentRoot(), addrs) at slot batchCount.
  function postBatch(
    address[] calldata addrs,
    uint256 newRoot,
    uint256 subtreeRoot,
    uint64 fromBlock,
    uint64 toBlock,
    bytes calldata proof
  ) external onlyOperator {
    uint256 id = batchCount;
    uint256 n = addrs.length;
    if (n == 0 || n > BATCH_SIZE || id >= MAX_BATCHES || newRoot >= FIELD || subtreeRoot >= FIELD) revert BadBatch();
    if (bond < MIN_BOND) revert BondTooLow();
    _checkSorted(addrs);
    _recordCurrentSigner();
    uint256 fromRoot = currentRoot();
    _verifyBatch(fromRoot, newRoot, id, subtreeRoot, addrs, proof);
    _record(id, newRoot, addrs);
    _rootBatch[newRoot] = id + 1;
    batchCount = id + 1;
    _emitBatch(id, fromRoot, newRoot, subtreeRoot, addrs, fromBlock, toBlock);
  }

  function _record(uint256 id, uint256 newRoot, address[] calldata addrs) internal {
    uint32 serial = ++posted;
    uint256 usableFrom = block.timestamp + CHALLENGE_PERIOD;
    if (id != 0 && batches[id - 1].usableFrom > usableFrom) usableFrom = batches[id - 1].usableFrom;
    batches[id] = BatchInfo({
      root: newRoot,
      listHash: _listHash(addrs),
      postedAt: uint64(block.timestamp),
      queueStart: uint64(_consumeQueue(addrs)),
      holds: 0,
      serial: serial,
      usableFrom: uint64(usableFrom)
    });
  }

  // =================================================================== bond (anyone, per depositor)

  /// @notice Add to the bond. The deposit stays the caller's (only it can withdraw it) until a slash.
  function addBond() external payable {
    _bond();
  }

  /// @notice Withdraw from the caller's own deposit, while no batch is in its challenge window and no dispute is
  ///   open (a pending batch and an open dispute are always covered). Fraud proofs stay possible afterwards; they
  ///   then drop the bad batches but pay only what is left.
  function withdrawBond(uint256 amount, address to) external {
    uint256 c = batchCount;
    if (openDisputes != 0 || (c != 0 && block.timestamp < batches[c - 1].usableFrom)) revert Pending();
    Deposit storage d = _deposits[msg.sender];
    if (d.epoch != slashEpoch || d.amount < amount) revert BondTooLow();
    d.amount -= uint192(amount);
    bond -= amount;
    emit BondWithdrawn(msg.sender, to, amount);
    _send(to, amount);
  }

  /// @notice `from`'s current deposit (0 after a slash).
  function depositOf(address from) external view returns (uint256) {
    Deposit memory d = _deposits[from];
    return d.epoch == slashEpoch ? d.amount : 0;
  }

  // =================================================================== fraud proofs (anyone)

  /// @notice The commitment `challenger` posts with `commit` one block or more before `challenge` /
  ///   `disputeOrigin` for entry `index` of batch `id`. `salt` keeps it unguessable.
  function commitHash(address challenger, uint256 id, uint256 index, bytes32 salt) public pure returns (bytes32) {
    return keccak256(abi.encode(challenger, id, index, salt));
  }

  /// @notice Step 1 of a challenge or dispute (front-running protection): see commitHash.
  function commit(bytes32 commitment) external {
    if (commits[commitment] == 0) commits[commitment] = block.number;
    emit Committed(commitment, msg.sender);
  }

  /// @notice Prove that batch `id` lists a non-holder (at any time): `addrs` is the batch's list (from its `Batch`
  ///   event), `index` the bad entry, `salt` the one of the caller's earlier `commit`. Only that one address is
  ///   checked. Drops batch `id` and every later batch and pays the whole bond to the caller.
  function challenge(uint256 id, uint256 index, address[] calldata addrs, bytes32 salt) external {
    BatchInfo storage b = _liveBatch(id, index, addrs);
    _useCommit(id, index, salt);
    address addr = addrs[index];
    if (_holds(addr)) revert IsHolder();
    (uint256 reward, uint256 dropped) = _drop(id, b.queueStart);
    emit Challenged(id, index, addr, msg.sender, reward, dropped);
    _send(msg.sender, reward);
  }

  /// @notice Claim, inside batch `id`'s challenge window (before its `usableFrom`, else `WindowClosed`), that entry
  ///   `index` holds an Agent ID that was not claimed through `HandleRegistry.register` (e.g. minted with
  ///   `adminRegister`). Takes DISPUTE_DEPOSIT and needs an earlier `commit`. At most one open dispute per address
  ///   and batch, and none for an address whose origin is already proven (`provenOrigin`). It holds the batch (and
  ///   every later one) until answered. Anyone can answer it until `answerBy` (now + CHALLENGE_PERIOD, fixed here
  ///   like the deposit, so a later `setParams` changes neither) with the address's registration signature
  ///   (`defendOrigin`); otherwise `resolveOrigin` drops the batch like a challenge. Only the window: a root that
  ///   became usable is never dropped by a dispute its operator did not answer in time.
  function disputeOrigin(uint256 id, uint256 index, address[] calldata addrs, bytes32 salt)
    external
    payable
    returns (uint256 dispute)
  {
    if (msg.value != DISPUTE_DEPOSIT) revert WrongDeposit();
    BatchInfo storage b = _liveBatch(id, index, addrs);
    if (block.timestamp >= b.usableFrom) revert WindowClosed();
    _useCommit(id, index, salt);
    address addr = addrs[index];
    if (!_holds(addr)) revert NotHolder(); // a non-holder: use `challenge`
    _claimDispute(b.serial, addr);
    _recordCurrentSigner();
    // the batch (and every later one) stays unusable until the dispute is answered
    b.holds++;
    if (id < heldFrom) heldFrom = id;
    dispute = disputeCount++;
    disputes[dispute] = Dispute({
      disputer: msg.sender,
      openedAt: uint64(block.timestamp),
      batchId: uint32(id),
      addr: addr,
      postedAt: b.postedAt,
      index: uint16(index),
      holds: true,
      listHash: b.listHash,
      serial: b.serial,
      answerBy: uint64(block.timestamp + CHALLENGE_PERIOD),
      deposit: uint96(msg.value)
    });
    openDisputes++;
    emit OriginDisputed(dispute, id, index, addr, msg.sender);
  }

  /// @notice Answer a dispute with the SPACE ID backend's signature of the address's registration (the `deadline`
  ///   and `sig` arguments of its `HandleRegistry.register` transaction). Pays the dispute's deposit to the caller. The origin
  ///   is then proven for good: a dispute of the same address in another batch is answered without a signature
  ///   (any `deadline` / `sig`; `signer` 0 in the event).
  function defendOrigin(uint256 dispute, uint256 deadline, bytes calldata sig) external {
    Dispute memory d = _openDispute(dispute);
    address s;
    if (!provenOrigin[d.addr]) {
      _recordCurrentSigner();
      s = _registrationSigner(d.addr, deadline, sig);
      if (s == address(0)) revert NotRegistered();
      provenOrigin[d.addr] = true;
    }
    emit OriginDefended(dispute, d.addr, s, msg.sender);
    _send(msg.sender, d.deposit);
  }

  /// @notice From the dispute's `answerBy` on, without a defence: drops the disputed batch and every later one and pays the
  ///   whole bond plus the deposit to the disputer. If that batch is already gone (an earlier fraud proof), only the
  ///   deposit is returned.
  function resolveOrigin(uint256 dispute) external {
    Dispute memory d = disputes[dispute];
    if (d.disputer == address(0) || block.timestamp < d.answerBy) revert NotOpen();
    _openDispute(dispute);
    uint256 id = d.batchId;
    BatchInfo storage b = batches[id];
    uint256 reward;
    if (id < batchCount && b.postedAt == d.postedAt && b.listHash == d.listHash) {
      uint256 dropped;
      (reward, dropped) = _drop(id, b.queueStart);
      emit Challenged(id, d.index, d.addr, d.disputer, reward, dropped);
    } else {
      emit DisputeVoid(dispute);
    }
    _send(d.disputer, reward + d.deposit);
  }

  /// @notice Accept the registry's current `signer()` for good (anyone; call it after every `SignerChanged`), so
  ///   registrations it signed stay defensible after a rotation.
  function recordSigner() external {
    _recordCurrentSigner();
  }

  // =================================================================== forced inclusion (anyone)

  /// @notice Force `addr` into the operator's next batches (free). `deadline` / `sig` are the SPACE ID backend's
  ///   registration signature for `addr` (from its `HandleRegistry.register` transaction), so only user-registered
  ///   holders can be forced in. Reveals interest in MurkFun when a holder enqueues itself: for disputes only. An
  ///   operator that stops posting stalls the queue too (nobody else can post; the owner can replace the operator).
  ///   Each address at most once, ever (`AlreadyEnqueued`): an address that is already in the tree is included again
  ///   (a harmless duplicate leaf), so re-enqueueing included holders costs the operator at most one leaf per holder.
  ///   A fraud proof that drops a batch puts the entries it consumed back in the queue (they need no new enqueue).
  function enqueue(address addr, uint256 deadline, bytes calldata sig) external {
    _recordCurrentSigner();
    if (enqueued[addr]) revert AlreadyEnqueued();
    if (_registrationSigner(addr, deadline, sig) == address(0)) revert NotRegistered();
    enqueued[addr] = true;
    provenOrigin[addr] = true;
    uint256 pos = queueTail++;
    queue[pos] = addr;
    queuedTime[pos] = uint64(block.timestamp);
    emit Enqueued(pos, addr);
  }

  // =================================================================== views

  /// @notice Root after the last live batch (pending or accepted); EMPTY_ROOT before the first.
  function currentRoot() public view returns (uint256) {
    uint256 c = batchCount;
    return c == 0 ? EMPTY_ROOT : batches[c - 1].root;
  }

  /// @notice Whether `root` may be used in an order proof: the root of a live batch past its challenge window, with
  ///   fewer than ROOT_HISTORY newer batches accepted.
  function isKnownRoot(uint256 root) external view returns (bool) {
    uint256 id = _rootBatch[root];
    if (id == 0) return false;
    id--;
    uint256 c = batchCount;
    if (id >= c || batches[id].root != root || !_accepted(id)) return false;
    uint256 newer = id + ROOT_HISTORY;
    return newer >= c || !_accepted(newer);
  }

  /// @notice Latest accepted root (0 if none yet). Clients prove against it.
  function acceptedRoot() external view returns (uint256 root, uint256 id) {
    for (uint256 c = batchCount; c > 0; c--) {
      if (_accepted(c - 1)) return (batches[c - 1].root, c - 1);
    }
  }

  /// @notice Queue entries not yet consumed.
  function queueLength() external view returns (uint256) {
    return queueTail - queueHead;
  }

  /// @notice The signer of `addr`'s registration signature (`deadline`, `sig`) if it is a known one, else 0.
  function registrationSigner(address addr, uint256 deadline, bytes calldata sig) external view returns (address) {
    return _registrationSigner(addr, deadline, sig);
  }

  // =================================================================== internals

  /// @dev The batch must include the queue entries from queueHead on, in order, as many as fit (at most
  ///   addrs.length, so the walk is bounded by the batch), except entries younger than QUEUE_GRACE: the batch takes
  ///   those it includes and stops at the first it does not (entries are in time order, so every later one is
  ///   younger still). The entries are distinct (one per address), so each entry found is a distinct leaf. `addrs`
  ///   is sorted, so each is found by binary search. Returns the queue head before.
  function _consumeQueue(address[] calldata addrs) internal returns (uint256 head) {
    head = queueHead;
    uint256 tail = queueTail;
    uint256 n = addrs.length;
    uint256 pos = head;
    for (; pos < tail && pos - head < n; pos++) {
      if (!_contains(addrs, queue[pos])) {
        if (block.timestamp < queuedTime[pos] + QUEUE_GRACE) break;
        revert QueueNotConsumed(pos);
      }
    }
    queueHead = pos;
  }

  /// @dev Accept the registry's current signer for good (cheap once known).
  function _recordCurrentSigner() internal {
    address s = IHandleRegistry(address(AGENT_NFT)).signer();
    if (s == address(0) || knownSigner[s]) return;
    knownSigner[s] = true;
    emit SignerRecorded(s);
  }

  function _contains(address[] calldata addrs, address a) internal pure returns (bool) {
    uint256 lo;
    uint256 hi = addrs.length;
    while (lo < hi) {
      uint256 mid = (lo + hi) >> 1;
      address m = addrs[mid];
      if (m == a) return true;
      if (m < a) lo = mid + 1;
      else hi = mid;
    }
    return false;
  }

  /// @dev Strictly increasing raw words, the first > 0: no zero address, no duplicate in the batch.
  function _checkSorted(address[] calldata addrs) internal pure {
    bool ok = true;
    assembly ("memory-safe") {
      let prev := 0
      let end := add(addrs.offset, shl(5, addrs.length))
      for { let p := addrs.offset } lt(p, end) { p := add(p, 0x20) } {
        let a := calldataload(p)
        if iszero(gt(a, prev)) {
          ok := 0
          break
        }
        prev := a
      }
    }
    if (!ok) revert NotSorted();
  }

  function _liveBatch(uint256 id, uint256 index, address[] calldata addrs) internal view returns (BatchInfo storage b) {
    if (id >= batchCount) revert NotLive();
    b = batches[id];
    if (_listHash(addrs) != b.listHash || index >= addrs.length) revert WrongList();
  }

  /// @dev One open dispute per address and batch, none for a proven origin.
  function _claimDispute(uint32 serial, address addr) internal {
    if (provenOrigin[addr]) revert OriginProven();
    bytes32 key = _disputeKey(serial, addr);
    if (disputeOpen[key]) revert AlreadyDisputed();
    disputeOpen[key] = true;
  }

  function _disputeKey(uint32 serial, address addr) internal pure returns (bytes32) {
    return keccak256(abi.encode(serial, addr));
  }

  function _useCommit(uint256 id, uint256 index, bytes32 salt) internal {
    bytes32 h = commitHash(msg.sender, id, index, salt);
    uint256 at = commits[h];
    if (at == 0 || at >= block.number) revert NoCommit();
    delete commits[h];
  }

  function _openDispute(uint256 dispute) internal returns (Dispute memory d) {
    d = disputes[dispute];
    if (d.disputer == address(0)) revert NotOpen();
    delete disputes[dispute];
    delete disputeOpen[_disputeKey(d.serial, d.addr)];
    openDisputes--;
    if (d.holds) _release(d.batchId, d.serial);
  }

  /// @dev An in-window dispute of batch `id` (posted as `serial`) is closed: one hold less, and `heldFrom` moves to
  ///   the next held live batch once `id` has none left. A dispute of a batch that was dropped (its slot gone or
  ///   re-posted) holds nothing any more.
  function _release(uint256 id, uint32 serial) internal {
    BatchInfo storage b = batches[id];
    if (id >= batchCount || b.serial != serial || b.holds == 0) return;
    if (--b.holds != 0 || heldFrom != id) return;
    uint256 c = batchCount;
    uint256 next = NONE;
    for (uint256 i = id + 1; i < c; i++) {
      if (batches[i].holds != 0) {
        next = i;
        break;
      }
    }
    heldFrom = next;
  }

  /// @dev Drops batch `id` and every later one, restores the queue they consumed, slashes the whole bond.
  function _drop(uint256 id, uint256 queueStart) internal returns (uint256 reward, uint256 dropped) {
    dropped = batchCount - id;
    batchCount = id;
    if (heldFrom >= id) heldFrom = NONE; // the held batches are gone (holds of earlier batches stay below `id`)
    queueHead = queueStart; // queue entries of dropped batches must be included again
    reward = bond;
    bond = 0;
    slashEpoch++;
  }

  /// @dev balanceOf > 0. A reverting balanceOf reverts the caller: a failed read never counts as "no Agent ID" (that
  ///   would let a `challenge` drop batches of holders). Listed addresses are never 0 (`_checkSorted`).
  function _holds(address a) internal view returns (bool) {
    return AGENT_NFT.balanceOf(a) != 0;
  }

  /// @dev The known signer of HandleRegistry's Register(keccak(handleOf(addr)), addr, deadline) digest, else 0.
  function _registrationSigner(address addr, uint256 deadline, bytes calldata sig) internal view returns (address) {
    IHandleRegistry r = IHandleRegistry(address(AGENT_NFT));
    bytes memory handle = bytes(r.handleOf(addr));
    if (handle.length == 0) return address(0);
    bytes32 digest = keccak256(
      abi.encodePacked(
        "\x19\x01", REGISTRY_DOMAIN, keccak256(abi.encode(REGISTER_TYPEHASH, keccak256(handle), addr, deadline))
      )
    );
    (address s, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
    if (err != ECDSA.RecoverError.NoError || s == address(0)) return address(0);
    return knownSigner[s] || s == r.signer() ? s : address(0);
  }

  /// @dev Past its challenge window and not held by an unanswered in-window dispute (of it or an earlier batch).
  function _accepted(uint256 id) internal view returns (bool) {
    return block.timestamp >= batches[id].usableFrom && id < heldFrom;
  }

  /// @dev circuits/batch public inputs: old_root, new_root, batch_index, count, subtree_root, addrs[1024] (padded).
  ///   The addresses are copied as raw calldata words: a word with dirty upper bits is not a 160-bit value, which the
  ///   circuit rejects (assert_max_bit_size), so no proof exists for it and the emitted list always equals the proven
  ///   one.
  function _verifyBatch(
    uint256 fromRoot,
    uint256 newRoot,
    uint256 id,
    uint256 subtreeRoot,
    address[] calldata addrs,
    bytes calldata proof
  ) internal view {
    // verify(bytes proof, bytes32[] publicInputs) calldata built in place (the compiler's encoder copies the
    // 1029-word array element by element)
    address v = address(BATCH_VERIFIER);
    bytes4 sel = IVerifier.verify.selector;
    bool ok;
    assembly ("memory-safe") {
      let p := mload(0x40)
      let plen := proof.length
      let ppad := and(add(plen, 31), not(31))
      let piAt := add(p, add(0x64, ppad)) // pi length word
      mstore(p, sel)
      mstore(add(p, 0x04), 0x40)
      mstore(add(p, 0x24), add(0x60, ppad))
      mstore(add(p, 0x44), plen)
      mstore(add(add(p, 0x64), sub(ppad, 0x20)), 0) // zero the proof's last (padded) word
      calldatacopy(add(p, 0x64), proof.offset, plen)
      mstore(piAt, 1029) // 5 + BATCH_SIZE
      mstore(add(piAt, 0x20), fromRoot)
      mstore(add(piAt, 0x40), newRoot)
      mstore(add(piAt, 0x60), id)
      mstore(add(piAt, 0x80), addrs.length)
      mstore(add(piAt, 0xa0), subtreeRoot)
      let a := add(piAt, 0xc0)
      let alen := shl(5, addrs.length)
      calldatacopy(a, addrs.offset, alen)
      calldatacopy(add(a, alen), calldatasize(), sub(0x8000, alen)) // zero padding up to 1024 words
      let size := sub(add(a, 0x8000), p)
      let success := staticcall(gas(), v, p, size, 0, 0x20)
      // read the result after the call (Yul evaluates arguments right to left)
      ok := and(success, and(gt(returndatasize(), 0x1f), eq(mload(0), 1)))
    }
    if (!ok) revert InvalidProof();
  }

  /// @dev keccak256(abi.encodePacked(addrs)) of clean addresses, over the raw calldata words.
  function _listHash(address[] calldata addrs) internal pure returns (bytes32 h) {
    assembly ("memory-safe") {
      let p := mload(0x40)
      let len := shl(5, addrs.length)
      calldatacopy(p, addrs.offset, len)
      h := keccak256(p, len)
    }
  }

  /// @dev `emit Batch(id, fromRoot, newRoot, subtreeRoot, addrs, fromBlock, toBlock)`, ABI-encoded by hand: the
  ///   compiler's encoder re-validates every address (about 0.4 gas-k per address); these are the proven words.
  function _emitBatch(
    uint256 id,
    uint256 fromRoot,
    uint256 newRoot,
    uint256 subtreeRoot,
    address[] calldata addrs,
    uint64 fromBlock,
    uint64 toBlock
  ) internal {
    bytes32 topic = Batch.selector;
    assembly ("memory-safe") {
      let p := mload(0x40)
      mstore(p, fromRoot)
      mstore(add(p, 0x20), newRoot)
      mstore(add(p, 0x40), subtreeRoot)
      mstore(add(p, 0x60), 0xc0) // offset of addrs
      mstore(add(p, 0x80), fromBlock)
      mstore(add(p, 0xa0), toBlock)
      mstore(add(p, 0xc0), addrs.length)
      let len := shl(5, addrs.length)
      calldatacopy(add(p, 0xe0), addrs.offset, len)
      log2(p, add(0xe0, len), topic, id)
    }
  }

  function _bond() internal {
    Deposit storage d = _deposits[msg.sender];
    uint64 e = slashEpoch;
    if (d.epoch != e) (d.amount, d.epoch) = (0, e);
    d.amount += uint192(msg.value);
    bond += msg.value;
    emit Bonded(msg.sender, msg.value);
  }

  function _send(address to, uint256 amount) internal {
    if (amount == 0) return;
    (bool ok,) = to.call{value: amount}("");
    if (!ok) revert TransferFailed();
  }
}
