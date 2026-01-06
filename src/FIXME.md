# Linux inclusion gaps

Issues to address before upstreaming:

- [medium] sequence_number is incremented in two contexts without shared sync, so KCSAN can flag a race and ordering can regress if both paths run: hws_irq.c:147, hws_video.c:279.
- [medium] cap_active is written without WRITE_ONCE while readers use READ_ONCE, which is a data race on SMP: hws_video.c:534.
- [medium] Default pix.half_size ignores the 2048-byte alignment requirement, so seed programming can write a misaligned half size before format negotiation: hws_video.c:381, hws_pci.c:286.
- [low] Non-ASCII characters in comments/strings will trigger checkpatch warnings: hws_reg.h:65, hws.h:55, hws_v4l2_ioctl.c:504.
- [low] Space-indented lines break kernel style (tabs required): hws_v4l2_ioctl.c:524, hws_v4l2_ioctl.c:525.
- [low] FIXME left in fast path; reviewers will likely ask to resolve or justify: hws_video.c:712.
- [low] Driver forces legacy INTx and never attempts MSI/MSI-X; upstream may request MSI support: hws_pci.c:404.
