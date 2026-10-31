#!/usr/bin/env python3
# Derive the sail-riscv RV32IM configs used by the cross-validation from the simulator's own
# `--rv32 --print-default-config` output (JSON with // comments).
#   usage: mkconfig.py rv32-default.json outdir
# Writes:
#   rv32im-strict.json  : only I + M (+ Zicsr, which machine-mode traps need), RAM = [0, 64 MiB) exactly like
#                         rv_step's 2^24-word memory, nothing else mapped (CLINT / dtb moved out of the
#                         address space), misaligned scalar load/store -> AlignmentException (rv_step's choice).
#   rv32im-relaxed.json : same, but misaligned load/store allowed (sail's default) and Zifencei on - shows where
#                         rv_step's deliberate TRAP choices differ from a common RV32IM_Zifencei core.
import json, re, sys, copy
src, out = sys.argv[1], sys.argv[2]
s = re.sub(r'^\s*//.*$', '', open(src).read(), flags=re.M)
c = json.loads(s)
KEEP = {'M', 'Zicsr'}
for k, v in c['extensions'].items():
    if isinstance(v, dict) and 'supported' in v:
        v['supported'] = k in KEEP
    if isinstance(v, dict) and 'mutable_misa' in v:
        v['mutable_misa'] = False
c['extensions']['V']['support_level'] = 'Disabled'
for k in ('Smstateen', 'Ssstateen'):
    c['extensions']['Stateen'][k]['supported'] = False
c['memory']['physaddr_bits'] = 32
c['base']['hpmevent_width_bits'] = 32
# Sv32 etc. need S; Svbare is the "no translation" mode, keep it
for k in ('Svbare',):
    if k in c['extensions']: c['extensions'][k]['supported'] = True
for k in ('fs_legal_states', 'vs_legal_states'):
    c['base']['mstatus'][k] = 'ExtContext_Off'
ram = copy.deepcopy(c['memory']['regions'][-1])
ram['base'] = {'len': 64, 'value': '0x0'}
ram['size'] = {'len': 64, 'value': '0x4000000'}          # 2^24 words = 64 MiB
ram['attributes']['misaligned_exceptions']['load_store'] = {'Some': 'AlignmentException'}
ram['attributes']['atomic_support'] = 'AMONone'
ram['attributes']['reservability'] = 'RsrvNone'
c['memory']['regions'] = [ram]
c['memory']['misaligned']['exceptions']['load_store'] = {'Some': 'AlignmentException'}
c['memory']['dtb_address'] = {'len': 64, 'value': '0xF0000000'}
c['platform']['clint']['supported'] = False
c['platform']['clint']['base'] = 0xE0000000
if 'simple_interrupt_generator' in c['platform']:
    c['platform']['simple_interrupt_generator']['supported'] = False
    c['platform']['simple_interrupt_generator']['base'] = 0xD0000000
json.dump(c, open(out + '/rv32im-strict.json', 'w'), indent=1)
m = copy.deepcopy(c)
m['memory']['misaligned']['exceptions']['load_store'] = {'None': None}
m['memory']['regions'][0]['attributes']['misaligned_exceptions']['load_store'] = {'None': None}
m['extensions']['Zifencei']['supported'] = True
json.dump(m, open(out + '/rv32im-relaxed.json', 'w'), indent=1)
print('ok')
