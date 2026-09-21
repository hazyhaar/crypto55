package c2torture

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2block"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/c2crypto"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/evm256"
	"code.hazyhaar.fr/devhoros/crypto55/pkg/statetrie"
)

// Ce fichier fournit un harnais de lecture et d'exécution des fixtures
// GeneralStateTests de la Fondation Ethereum (format JSON d'ethereum/tests).
// Il n'embarque aucun cas « officiel » fabriqué : les fixtures réelles doivent
// être vendues sous testdata/ ou fournies par l'appelant.
//
// Le harnais résout l'émetteur de manière bit-exacte à partir de la clé
// privée secp256k1 via c2crypto.AddressFromPrivateKey lorsque la fixture
// ne porte que `secretKey` (format standard d'ethereum/tests).

var (
	// ErrHexLiteral signale un littéral 0x... malformé.
	ErrHexLiteral = errors.New("c2torture: hex literal 0x invalide")
	// ErrFixture signale une fixture structurellement incohérente.
	ErrFixture = errors.New("c2torture: fixture GeneralStateTests invalide")
	// ErrSenderUnresolved signale qu'un émetteur ne peut être résolu.
	ErrSenderUnresolved = errors.New("c2torture: émetteur non résolu")
	// ErrTypeNotSupported signale un type de transaction non supporté par la fourche considérée.
	ErrTypeNotSupported = errors.New("c2torture: type de transaction non supporté (TR_TypeNotSupported)")
)

// HexBytes décode un littéral hexadécimal Ethereum préfixé par 0x. Le préfixe
// 0x est obligatoire ; une longueur impaire est complétée à gauche par un zéro,
// conformément à l'usage des fixtures.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: %v", ErrHexLiteral, err)
	}
	b, err := parseHexLiteral(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// HexU256 décode un scalaire 256 bits au format 0x... (big-endian).
type HexU256 evm256.Uint256

func (h *HexU256) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: %v", ErrHexLiteral, err)
	}
	b, err := parseHexLiteral(s)
	if err != nil {
		return err
	}
	if len(b) > 32 {
		return fmt.Errorf("%w: scalaire de %d octets > 32", ErrHexLiteral, len(b))
	}
	*h = HexU256(evm256.FromBytesBE(b))
	return nil
}

// U256 renvoie la valeur 256 bits sous-jacente.
func (h HexU256) U256() evm256.Uint256 { return evm256.Uint256(h) }

func parseHexLiteral(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return nil, fmt.Errorf("%w: %q sans préfixe 0x", ErrHexLiteral, s)
	}
	raw := s[2:]
	if raw == "" {
		return nil, nil
	}
	if len(raw)%2 == 1 {
		raw = "0" + raw
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrHexLiteral, s, err)
	}
	return b, nil
}

// STAccount décrit un compte de la section `pre` (et, par symétrie, de toute
// section d'état explicite).
type STAccount struct {
	Nonce    HexU256            `json:"nonce"`
	Balance  HexU256            `json:"balance"`
	Code     HexBytes           `json:"code"`
	CodeHash HexBytes           `json:"codeHash"`
	Storage  map[string]HexU256 `json:"storage"`
}

// STEnv décrit l'environnement de bloc d'une fixture.
type STEnv struct {
	CurrentCoinbase   HexBytes `json:"currentCoinbase"`
	CurrentGasLimit   HexU256  `json:"currentGasLimit"`
	CurrentNumber     HexU256  `json:"currentNumber"`
	CurrentTimestamp  HexU256  `json:"currentTimestamp"`
	CurrentDifficulty HexU256  `json:"currentDifficulty"`
	CurrentBaseFee    HexU256  `json:"currentBaseFee"`
	PreviousHash      HexBytes `json:"previousHash"`
}

// STAccessTuple décrit un tuple d'accès d'une liste d'accès EIP-2930 / EIP-1559.
type STAccessTuple struct {
	Address     HexBytes   `json:"address"`
	StorageKeys []HexBytes `json:"storageKeys"`
}

// STTransaction est la transaction de la fixture. Supporte le mode Legacy,
// EIP-2930 et EIP-1559 (avec maxFeePerGas / maxPriorityFeePerGas et accessLists).
type STTransaction struct {
	Data                 []HexBytes        `json:"data"`
	GasLimit             []HexU256         `json:"gasLimit"`
	GasPrice             *HexU256          `json:"gasPrice,omitempty"`
	MaxFeePerGas         *HexU256          `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *HexU256          `json:"maxPriorityFeePerGas,omitempty"`
	Nonce                HexU256           `json:"nonce"`
	SecretKey            HexBytes          `json:"secretKey"`
	Sender               HexBytes          `json:"sender"`
	To                   HexBytes          `json:"to"`
	Value                []HexU256         `json:"value"`
	AccessLists          []json.RawMessage `json:"accessLists,omitempty"`
	AccessList           []STAccessTuple   `json:"accessList,omitempty"`
}

// STPostEntry est une entrée attendue d'une fourche de la section `post`.
type STPostEntry struct {
	Hash            HexBytes `json:"hash"`
	Logs            HexBytes `json:"logs"`
	TxBytes         HexBytes `json:"txbytes"`
	ExpectException string   `json:"expectException,omitempty"`
	Indexes         struct {
		Data  int `json:"data"`
		Gas   int `json:"gas"`
		Value int `json:"value"`
	} `json:"indexes"`
}

// StateTestFixture est une fixture GeneralStateTests nommée.
type StateTestFixture struct {
	Env         STEnv                    `json:"env"`
	Pre         map[string]STAccount     `json:"pre"`
	Transaction STTransaction            `json:"transaction"`
	Post        map[string][]STPostEntry `json:"post"`
}

// SenderResolver résout l'adresse d'un émetteur à partir de sa clé privée.
type SenderResolver func(secretKey []byte) (c2block.Address, error)

// DefaultSenderResolver dérive l'adresse secp256k1 canonique depuis une clé
// privée de 32 octets (complétée à gauche par des zéros si inférieure à 32 octets).
func DefaultSenderResolver(secretKey []byte) (c2block.Address, error) {
	if len(secretKey) == 0 {
		return c2block.Address{}, ErrSenderUnresolved
	}
	if len(secretKey) > 32 {
		return c2block.Address{}, fmt.Errorf("%w: secretKey de %d octets > 32", ErrFixture, len(secretKey))
	}
	var seckey [32]byte
	copy(seckey[32-len(secretKey):], secretKey)
	addr, err := c2crypto.AddressFromPrivateKey(seckey[:])
	if err != nil {
		return c2block.Address{}, fmt.Errorf("%w: %v", ErrSenderUnresolved, err)
	}
	return c2block.Address(addr), nil
}

// UnresolvedSenderResolver refuse toute clé et ne fabrique jamais d'adresse
// (utilisé pour les tests de sentinelle négative).
func UnresolvedSenderResolver([]byte) (c2block.Address, error) {
	return c2block.Address{}, ErrSenderUnresolved
}

// ParseStateTestFile décode un document ethereum/tests. Le document est un
// objet JSON dont chaque clé est un nom de cas ; les clés préfixées par `_`
// (métadonnées) sont ignorées.
func ParseStateTestFile(data []byte) (map[string]*StateTestFixture, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFixture, err)
	}
	out := make(map[string]*StateTestFixture, len(raw))
	for name, body := range raw {
		if strings.HasPrefix(name, "_") {
			continue
		}
		var f StateTestFixture
		if err := json.Unmarshal(body, &f); err != nil {
			return nil, fmt.Errorf("%w: cas %q: %v", ErrFixture, name, err)
		}
		out[name] = &f
	}
	return out, nil
}

// LoadStateTestCorpus parcourt récursivement un répertoire et agrège toutes les
// fixtures .json rencontrées. Un répertoire absent rend une erreur de système
// de fichiers, afin que l'appelant décide ou non de passer le test.
func LoadStateTestCorpus(root string) (map[string]*StateTestFixture, error) {
	out := make(map[string]*StateTestFixture)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fixtures, err := ParseStateTestFile(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for name, f := range fixtures {
			out[name] = f
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func hexToAddress(b []byte) (c2block.Address, error) {
	if len(b) > 20 {
		return c2block.Address{}, fmt.Errorf("%w: adresse de %d octets > 20", ErrFixture, len(b))
	}
	var a c2block.Address
	copy(a[20-len(b):], b)
	return a, nil
}

func hexU256ToU64(z evm256.Uint256) (uint64, error) {
	if z[1]|z[2]|z[3] != 0 {
		return 0, fmt.Errorf("%w: valeur > uint64", ErrFixture)
	}
	return z[0], nil
}

func pickBytes(list []HexBytes, idx int) (HexBytes, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if idx < 0 || idx >= len(list) {
		return nil, fmt.Errorf("%w: index data=%d hors plage %d", ErrFixture, idx, len(list))
	}
	return list[idx], nil
}

func pickU256(list []HexU256, idx int) (HexU256, error) {
	if len(list) == 0 {
		return HexU256{}, nil
	}
	if idx < 0 || idx >= len(list) {
		return HexU256{}, fmt.Errorf("%w: index hors plage %d", ErrFixture, idx)
	}
	return list[idx], nil
}

// SeedState construit un StateTrie initialisé depuis la section `pre` :
// nonce, balance, code (empreinte keccak scellée) et stockage slot par slot.
// L'ordre d'insertion est trié pour rester déterministe.
func (f *StateTestFixture) SeedState() (*statetrie.StateTrie, error) {
	if f == nil {
		return nil, ErrFixture
	}
	st := statetrie.NewStateTrie()
	keys := make([]string, 0, len(f.Pre))
	for k := range f.Pre {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		account := f.Pre[k]
		rawAddr, err := parseHexLiteral(k)
		if err != nil {
			return nil, fmt.Errorf("pre[%s]: %w", k, err)
		}
		addr, err := hexToAddress(rawAddr)
		if err != nil {
			return nil, err
		}
		u := addrToU256(addr)
		nonce, err := hexU256ToU64(account.Nonce.U256())
		if err != nil {
			return nil, fmt.Errorf("pre[%s].nonce: %w", k, err)
		}
		acc := &statetrie.Account{
			Nonce:   nonce,
			Balance: account.Balance.U256(),
		}
		code := []byte(account.Code)
		if len(code) > 0 {
			acc.Code = append([]byte(nil), code...)
			var h [32]byte
			c2crypto.Keccak256(code, &h)
			acc.CodeHash = h
		} else if len(account.CodeHash) == 32 {
			copy(acc.CodeHash[:], account.CodeHash)
		}
		st.SetAccount(&u, acc)

		slots := make([]string, 0, len(account.Storage))
		for sk := range account.Storage {
			slots = append(slots, sk)
		}
		sort.Strings(slots)
		for _, sk := range slots {
			rawSlot, err := parseHexLiteral(sk)
			if err != nil {
				return nil, fmt.Errorf("pre[%s].storage[%s]: %w", k, sk, err)
			}
			if len(rawSlot) > 32 {
				return nil, fmt.Errorf("%w: slot > 32 octets", ErrFixture)
			}
			slot := evm256.FromBytesBE(rawSlot)
			val := account.Storage[sk].U256()
			st.SetStorage(&u, &slot, &val)
		}
	}
	return st, nil
}

// Header traduit l'environnement de la fixture en en-tête de bloc exploitable
// par c2block.BlockProcessor.
func (e STEnv) Header() (*c2block.BlockHeader, error) {
	h := &c2block.BlockHeader{}
	coinbase, err := hexToAddress(e.CurrentCoinbase)
	if err != nil {
		return nil, err
	}
	h.Coinbase = coinbase
	if h.GasLimit, err = hexU256ToU64(e.CurrentGasLimit.U256()); err != nil {
		return nil, err
	}
	if h.Number, err = hexU256ToU64(e.CurrentNumber.U256()); err != nil {
		return nil, err
	}
	if h.Timestamp, err = hexU256ToU64(e.CurrentTimestamp.U256()); err != nil {
		return nil, err
	}
	h.Difficulty = e.CurrentDifficulty.U256()
	h.BaseFee = e.CurrentBaseFee.U256()
	if len(e.PreviousHash) == 32 {
		copy(h.ParentHash[:], e.PreviousHash)
	}
	return h, nil
}

// BuildTransaction assemble la transaction exécutable pour un triplet
// d'indexes (data, gas, value). L'émetteur provient du champ `sender` étendu ou,
// à défaut, du résolveur fourni (ou DefaultSenderResolver si nil).
func (tx STTransaction) BuildTransaction(dataIdx, gasIdx, valueIdx int, resolve SenderResolver) (*c2block.Transaction, error) {
	out := &c2block.Transaction{Type: c2block.TxLegacy}
	data, err := pickBytes(tx.Data, dataIdx)
	if err != nil {
		return nil, err
	}
	gas, err := pickU256(tx.GasLimit, gasIdx)
	if err != nil {
		return nil, err
	}
	if out.Gas, err = hexU256ToU64(gas.U256()); err != nil {
		return nil, err
	}
	value, err := pickU256(tx.Value, valueIdx)
	if err != nil {
		return nil, err
	}
	out.Value = value.U256()

	if tx.MaxFeePerGas != nil {
		out.Type = c2block.TxDynamicFee
		out.GasFeeCap = tx.MaxFeePerGas.U256()
		if tx.MaxPriorityFeePerGas != nil {
			out.GasTipCap = tx.MaxPriorityFeePerGas.U256()
		} else {
			out.GasTipCap = out.GasFeeCap
		}
		out.GasPrice = out.GasFeeCap
	} else if tx.GasPrice != nil {
		out.GasPrice = tx.GasPrice.U256()
		out.GasFeeCap = out.GasPrice
		out.GasTipCap = out.GasPrice
	}

	if out.Nonce, err = hexU256ToU64(tx.Nonce.U256()); err != nil {
		return nil, err
	}
	out.Data = append([]byte(nil), data...)

	// Résolution de l'access list éventuelle (format tableau de listes ou liste simple)
	var rawTuples []STAccessTuple
	if len(tx.AccessLists) > 0 {
		if dataIdx < 0 || dataIdx >= len(tx.AccessLists) {
			return nil, fmt.Errorf("%w: index accessLists %d hors plage (taille %d)", ErrFixture, dataIdx, len(tx.AccessLists))
		}
		raw := tx.AccessLists[dataIdx]
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &rawTuples); err != nil {
				return nil, fmt.Errorf("%w: access list malformée: %v", ErrFixture, err)
			}
		}
	} else if len(tx.AccessList) > 0 {
		rawTuples = tx.AccessList
	}

	if len(rawTuples) > 0 {
		for _, tuple := range rawTuples {
			addr, err := hexToAddress(tuple.Address)
			if err != nil {
				return nil, err
			}
			var keys []c2block.Hash
			for _, sk := range tuple.StorageKeys {
				if len(sk) > 32 {
					return nil, fmt.Errorf("%w: storage key > 32 octets (%d)", ErrFixture, len(sk))
				}
				var k c2block.Hash
				copy(k[32-len(sk):], sk)
				keys = append(keys, k)
			}
			out.AccessList = append(out.AccessList, c2block.AccessTuple{
				Address:     addr,
				StorageKeys: keys,
			})
		}
		if out.Type == c2block.TxLegacy {
			out.Type = c2block.TxAccessList
		}
	}

	if len(tx.Sender) > 0 {
		out.From, err = hexToAddress(tx.Sender)
		if err != nil {
			return nil, err
		}
	} else {
		if resolve == nil {
			resolve = DefaultSenderResolver
		}
		out.From, err = resolve([]byte(tx.SecretKey))
		if err != nil {
			return nil, err
		}
	}
	if len(tx.To) > 0 {
		to, err := hexToAddress(tx.To)
		if err != nil {
			return nil, err
		}
		out.To = &to
	}
	return out, nil
}

// StateTestResult agrège le verdict d'exécution d'une entrée de fixture.
type StateTestResult struct {
	StateRoot  [32]byte
	GasUsed    uint64
	Receipt    *c2block.Receipt
	Err        error
	Mismatches []string
}

// RunForFork exécute la transaction de la fixture pour la fourche et le triplet
// d'indexes demandés. Si la transaction mobilise un type (ex: EIP-1559) non
// supporté par la fourche considérée, elle renvoie ErrTypeNotSupported.
func (f *StateTestFixture) RunForFork(fork string, dataIdx, gasIdx, valueIdx int, resolve SenderResolver) (*StateTestResult, error) {
	tx, err := f.Transaction.BuildTransaction(dataIdx, gasIdx, valueIdx, resolve)
	if err != nil {
		return nil, err
	}
	if tx.Type == c2block.TxDynamicFee {
		switch fork {
		case "London", "Paris", "Shanghai", "Cancun", "Prague":
			// Fourches supportant EIP-1559
		default:
			return &StateTestResult{Err: ErrTypeNotSupported}, ErrTypeNotSupported
		}
	}
	st, err := f.SeedState()
	if err != nil {
		return nil, err
	}
	header, err := f.Env.Header()
	if err != nil {
		return nil, err
	}
	receipt, err := c2block.NewBlockProcessor(st).ProcessTransaction(header, tx)
	if err != nil {
		return &StateTestResult{Err: err}, err
	}
	return &StateTestResult{
		StateRoot: st.ComputeRoot(),
		GasUsed:   receipt.GasUsed,
		Receipt:   receipt,
	}, nil
}

// Run exécute la transaction de la fixture sous les règles de la fourche par défaut (Cancun).
func (f *StateTestFixture) Run(dataIdx, gasIdx, valueIdx int, resolve SenderResolver) (*StateTestResult, error) {
	return f.RunForFork("Cancun", dataIdx, gasIdx, valueIdx, resolve)
}

// CheckPost confronte le résultat à l'entrée `post` de la fourche demandée,
// sélectionnée par triplet d'indexes. Elle compare la racine d'état (`post.hash`),
// l'empreinte Keccak-256 de la liste RLP des logs (`post.logs`), et valide
// l'adéquation d'une éventuelle exception attendue (`expectException`).
func (f *StateTestFixture) CheckPost(fork string, dataIdx, gasIdx, valueIdx int, res *StateTestResult) (bool, *StateTestResult, error) {
	if res == nil {
		return false, nil, ErrFixture
	}
	entries, ok := f.Post[fork]
	if !ok {
		return false, res, nil
	}
	for i := range entries {
		e := entries[i]
		if e.Indexes.Data != dataIdx || e.Indexes.Gas != gasIdx || e.Indexes.Value != valueIdx {
			continue
		}
		out := *res
		// Cas où une exception est attendue (ex: TR_TypeNotSupported)
		if e.ExpectException != "" {
			if res.Err == nil {
				out.Mismatches = append(out.Mismatches,
					fmt.Sprintf("exception attendue %q mais l'exécution a réussi sans erreur", e.ExpectException))
			}
			return true, &out, nil
		}
		if res.Err != nil {
			out.Mismatches = append(out.Mismatches,
				fmt.Sprintf("erreur d'exécution inattendue: %v", res.Err))
			return true, &out, nil
		}
		if len(e.Hash) != 32 {
			return false, res, fmt.Errorf("%w: post.hash de %d octets", ErrFixture, len(e.Hash))
		}
		var want [32]byte
		copy(want[:], e.Hash)
		if want != out.StateRoot {
			out.Mismatches = append(out.Mismatches,
				fmt.Sprintf("StateRoot obtenu=%x attendu=%x", out.StateRoot, want))
		}
		if len(e.Logs) > 0 {
			if len(e.Logs) != 32 {
				return false, res, fmt.Errorf("%w: post.logs de %d octets != 32", ErrFixture, len(e.Logs))
			}
			var wantLogs [32]byte
			copy(wantLogs[:], e.Logs)
			var gotLogs [32]byte
			if res.Receipt != nil {
				gotLogs = [32]byte(c2block.LogsHash(res.Receipt.Logs))
			} else {
				c2crypto.Keccak256([]byte{0xc0}, &gotLogs)
			}
			if wantLogs != gotLogs {
				out.Mismatches = append(out.Mismatches,
					fmt.Sprintf("LogsHash obtenu=%x attendu=%x", gotLogs, wantLogs))
			}
		}
		return true, &out, nil
	}
	return false, res, nil
}
