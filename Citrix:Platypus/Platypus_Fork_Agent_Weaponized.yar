rule Platypus_Fork_Agent_Weaponized
{
    meta:
        description = "Weaponized private fork of WangYihang/Platypus: agent binary containing the rootesc/selfpersist offensive packages absent from upstream"
        author = "Binary Defense"
        date = "2026-10-03"
        reference = "entretiensol[.]com Netscaler intrusion; Platypus 0.1.0-SNAPSHOT fork"
    strings:
        $mod       = "github.com/WangYihang/Platypus" ascii
        $rootesc   = "internal/agent/rootesc" ascii
        $selfpers  = "internal/agent/selfpersist" ascii
        $persist   = "self-persistence); do not edit" ascii
        $suid      = ".platypus-suid-" ascii
        $verify    = "rootesc-verify-root" ascii
    condition:
        // Go binary of this project PLUS at least two offensive markers that
        // upstream Platypus never contains -> weaponized fork, any OS/arch.
        $mod and 2 of ($rootesc, $selfpers, $persist, $suid, $verify)
}