# World opcode samples (raw)

Post-auth **world** opcode bodies the local world server logged as *unhandled*
during live client runs (`world_unhandled_w<run>_<opcode>.bin`, where `<opcode>`
is the opcode value in hex). Credential-free — these are in-world opcodes, not the
login handshake. A 0-byte file means that opcode arrived with an empty body.

Useful as ground truth for **which world opcodes the Ascension client emits** and
their body shapes, when deciding what `world_server.py` still needs to answer.
Opcode names ↔ values: see `../../docs/protocol/ascension-opcodes.txt` and
`../../docs/protocol/ascension-handler-map.txt`.
