"""Codex's mutation harness, adapted to the new generate() signature.

Every asserted property must fail when broken. A property that survives its own
mutation is a property check() does not actually test.
"""
import copy, io, contextlib, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import generate_conduct as g

orig = g.generate
FAILURES = []

def attempt(name, mutate, second_call_only=False):
    calls = [0]
    def gen():
        corpora, truth = copy.deepcopy(orig())
        if (not second_call_only) or calls[0]:
            mutate(corpora, truth)
        calls[0] += 1
        return corpora, truth
    g.generate = gen
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            g.check()
        print(f"{name}: PASSED   <-- property not tested"); FAILURES.append(name)
    except AssertionError as e:
        print(f"{name}: failed as it should: {e}")
    finally:
        g.generate = orig

attempt('determinism',        lambda c,t: c['benign_corpus'].pop(), True)
attempt('corpus_size',        lambda c,t: c['conduct_train'].clear())
attempt('benign_length',      lambda c,t: c['benign_corpus'].pop())
attempt('benign_tool_call',   lambda c,t: c['benign_corpus'][0].__setitem__('tool_name', None))
attempt('benign_label',       lambda c,t: c['benign_corpus'][0].__setitem__('label', 'x'))
attempt('train_unlabelled',   lambda c,t: c['conduct_train'][0].__setitem__('label', 'scope-violation'))
attempt('train_attack_marker',lambda c,t: c['conduct_train'][0].__setitem__('is_attack_event', True))

def family_in_sid(c, t):
    for e in c['holdout_sealed']:
        e['session_id'] = 's_hold_scope-violation_00'
attempt('family_in_session_id', family_in_sid)

def drop_attack_session(c, t):
    h = c['holdout_sealed']
    s = next(e['session_id'] for e in h if e['label'] == 'scope-violation')
    for e in h:
        if e['session_id'] == s:
            e['label'] = 'benign'; e['is_attack_event'] = False
attempt('attack_count', drop_attack_session)

attempt('window_overlap', lambda c,t: c['conduct_train'][0].__setitem__('ts', c['holdout_sealed'][0]['ts']))

def unmark(c, t):
    s = next(e['session_id'] for e in c['holdout_sealed'] if e['is_attack_event'])
    for e in c['holdout_sealed']:
        if e['session_id'] == s:
            e['is_attack_event'] = False
attempt('attack_event_marked', unmark)

def date_separator(c, t):
    # push every attack before every benign turn, the original leak
    for e in c['holdout_sealed']:
        if e['label'] not in (None, 'benign'):
            e['ts'] = '2026-08-16' + e['ts'][10:]
    for e in c['benign_corpus']:
        e['ts'] = '2026-08-29' + e['ts'][10:]
attempt('ts_separator', date_separator)

def amount_separator(c, t):
    for e in c['holdout_sealed']:
        if e['is_attack_event'] and e['amount_cents'] is not None:
            e['amount_cents'] = 900_000
    for e in c['benign_corpus']:
        if e['amount_cents'] is not None:
            e['amount_cents'] = 100
attempt('amount_separator', amount_separator)

attempt('scope_signal',  lambda c,t: next(e for e in c['holdout_sealed'] if e['tool_name'] and e['tool_name'] not in e['declared_scope']).__setitem__('label','benign'))
attempt('cross_signal',  lambda c,t: next(e for e in c['holdout_sealed'] if e['tool_name'] and e['target_tenant_id']!=e['tenant_id']).__setitem__('label','benign'))
attempt('injection_signal', lambda c,t: next(e for e in c['holdout_sealed'] if e['tool_name'] and e['ma_prompt_injection_score']>=.70).__setitem__('label','benign'))
attempt('benign_writes', lambda c,t: [e.update(tool_name='lookup_account', amount_cents=None) for e in c['benign_corpus'] if e['tool_name']=='issue_refund'])

def break_sequence(c, t):
    # the exact mutation that slipped through the first version
    for e in c['holdout_sealed']:
        if e['label'] == 'privilege-sequencing':
            e.update(tool_name=None, target_tenant_id=None, account_id=None, amount_cents=None)
attempt('privilege_sequencing_claim', break_sequence)

def benign_pairs(c, t):
    # force two rows into one session so the pairing actually exists; the
    # earlier version of this mutation was a no-op when the first corpus
    # session contributed only one tool-call turn
    a, b = c['benign_corpus'][0], c['benign_corpus'][1]
    b['session_id'] = a['session_id']
    a.update(tool_name='lookup_account', account_id='a_000001', turn_index=0)
    b.update(tool_name='issue_refund', account_id='a_000001', turn_index=1)
attempt('benign_no_pairing', benign_pairs)

attempt('predicate_vocabulary', lambda c,t: [e.pop('amount_cents') for e in c['holdout_sealed']])

def attack_only_verdict(c, t):
    # Give every privilege-sequencing session an ma_verdict no benign turn
    # carries. A candidate naming that one value then catches the whole family
    # and blocks nothing legitimate: the set-membership free pass, on a field
    # that is not that family's intended signal.
    for e in c['holdout_sealed']:
        if e['label'] == 'privilege-sequencing':
            e['ma_verdict'] = 'REVIEW'
attempt('no_value_set_free_pass', attack_only_verdict)

if FAILURES:
    print(f"\n{len(FAILURES)} properties are asserted but not actually tested: {FAILURES}")
    sys.exit(1)
print("\nevery asserted property fails when broken")
