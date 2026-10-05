rule Platypus_Fork_Bootstrap_Installer
{
    meta:
        description = "Platypus fork curl|sh enrollment/bootstrap script (drops OS/arch-matched agent from C2)"
        author = "Binary Defense"
        date = "2026-10-03"
    strings:
        $c1 = "Platypus agent bootstrap" ascii
        $c2 = "AGENT_TOKEN=" ascii
        $c3 = "AGENT_BIN_NAME=" ascii
        $c4 = "PLATYPUS_INGRESS_CA" ascii
        $c5 = "platypus: detected" ascii
    condition:
        filesize < 64KB and 3 of them
}