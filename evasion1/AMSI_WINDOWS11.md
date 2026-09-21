# AMSI / Windows 11 Notes

AMSI itself is not Windows 11-only. Microsoft documents the AMSI Win32 APIs for Windows 10 and later, and Microsoft's Defender AMSI demonstration lists Windows 10 and later as supported.

The imported research skill contains several version-sensitive AMSI bypass techniques. In particular, it describes context-signature corruption as a Windows 10-specific technique and notes that the relevant field location may differ on Windows 11. It also describes AMSI API-level techniques around AmsiOpenSession and AmsiScanBuffer.

Evasion1 intentionally does not implement an AMSI bypass. Instead P11 gives the detector a real, repeatable AMSI integrity test:

1. Initialize AMSI.
2. Open an AMSI session.
3. Submit Microsoft's deterministic AMSI demonstration sample.
4. Record the HRESULT and AMSI result.
5. Treat an unexpected clean result as an integrity/provider anomaly.
6. Release the session and context.

For Windows 11 research, capture the exact OS build, Defender engine/signature versions, process architecture, AMSI result, HRESULT, and repeatability. Do not hard-code internal amsi.dll offsets: servicing can change implementation details.

Microsoft's official AMSI demonstration is the reference for expected blocking behavior.