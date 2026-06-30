##! Mini-SOC — tagging MITRE ATT&CK léger côté Zeek.
##! Émet des Notice enrichis d'un champ `mitre` que Vector mappe ensuite
##! vers les tags de NetworkEvent. Détection volontairement simple et
##! lisible (pédagogique) : la détection lourde reste à Suricata.

@load base/frameworks/notice
@load base/protocols/conn

module MiniSOC;

export {
    redef enum Notice::Type += {
        ## Beaconing C2 probable : connexions répétées et régulières vers
        ## une même destination externe (T1071 / TA0011).
        Possible_Beacon,
        ## Scan horizontal : une source contacte de nombreux hôtes (T1046).
        Horizontal_Scan,
    };

    ## Nombre de connexions vers des destinations distinctes au-delà duquel
    ## on considère un scan horizontal.
    const horizontal_scan_threshold = 25 &redef;
    ## Fenêtre d'observation pour le scan.
    const scan_window = 60 sec &redef;
    ## Nombre de connexions vers la MÊME destination externe au-delà duquel
    ## on suspecte du beaconing.
    const beacon_threshold = 15 &redef;
    const beacon_window = 300 sec &redef;
}

# src -> ensemble des destinations contactées (scan horizontal)
global scan_targets: table[addr] of set[addr] &create_expire = scan_window;
# (src,dst) -> compteur de connexions (beaconing)
global beacon_counts: table[addr, addr] of count &create_expire = beacon_window &default = 0;

event connection_state_remove(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    # ── Scan horizontal : source locale ou externe qui touche bcp d'hôtes ──
    if ( orig !in scan_targets )
        scan_targets[orig] = set();
    add scan_targets[orig][resp];

    if ( |scan_targets[orig]| == horizontal_scan_threshold )
        {
        NOTICE([$note=Horizontal_Scan,
                $conn=c,
                $msg=fmt("Scan horizontal probable depuis %s (%d hotes contactes) [MITRE:T1046]",
                         orig, |scan_targets[orig]|),
                $sub="T1046",
                $identifier=fmt("hscan-%s", orig)]);
        }

    # ── Beaconing : connexions répétées vers une destination externe ──────
    if ( ! Site::is_local_addr(resp) && Site::is_local_addr(orig) )
        {
        ++beacon_counts[orig, resp];
        if ( beacon_counts[orig, resp] == beacon_threshold )
            {
            NOTICE([$note=Possible_Beacon,
                    $conn=c,
                    $msg=fmt("Beaconing probable %s -> %s (%d connexions) [MITRE:T1071]",
                             orig, resp, beacon_counts[orig, resp]),
                    $sub="T1071",
                    $identifier=fmt("beacon-%s-%s", orig, resp)]);
            }
        }
    }
