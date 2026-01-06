# Linux inclusion gaps

Issues to address before upstreaming:

- [medium] Default pix.half_size ignores the 2048-byte alignment requirement, so seed programming can write a misaligned half size before format negotiation: hws_video.c:381, hws_pci.c:286.
- [low] Driver forces legacy INTx and never attempts MSI/MSI-X; upstream may request MSI support: hws_pci.c:404.
