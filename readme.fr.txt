
Ce projet est destiné à lutter contre l'analyse de protocole DPI et à contourner le blocage de protocole.

L'un des moyens possibles pour surmonter l'analyse de signature DPI consiste à modifier le protocole.
Le moyen le plus rapide mais non le plus simple est de modifier le logiciel lui-même.
Pour TCP, obfsproxy existe. Cependant, dans le cas d'un VPN, seules les solutions pas très rapides (openvpn) fonctionnent sur TCP.

Que faire en cas d'upp?
Si les deux extrémités sont sur une adresse IP externe, il est possible de modifier les paquets au niveau IP.
Par exemple, si vous avez un SMV et que vous avez un routeur openwrt à la maison et une adresse IP externe du FAI,
alors vous pouvez utiliser cette technique. Si un point de terminaison est derrière NAT, les capacités sont limitées,
mais il est toujours possible de toucher aux en-têtes udp / tcp et aux données utiles.

Le schéma est le suivant:
 homologue 1 <=> obfuscateur / déobfuscateur IP <=> réseau <=> obfuscateur / désobfuscateur IP <=> homologue 2

Pour qu'un paquet soit livré de l'homologue 1 à l'homologue 2, les deux ayant des adresses IP externes,
il suffit d'avoir des en-têtes IP corrects. Vous pouvez définir n’importe quel numéro de protocole, masquer ou chiffrer la charge IP,
y compris les en-têtes tcp / udp. Le DPI ne comprendra pas de quoi il s'agit.
Il verra les protocoles IP non standard avec un contenu inconnu.

ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid
ipobfs
------

NFQUEUE queue handler, IP obfuscator/deobfuscator.

 --qnum=<nfqueue_number>
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --debug                        ; print debug info
 --uid=uid[:gid]                ; drop root privs
 --ipproto-xor=0..255|0x00-0xFF ; xor protocol ID with given value
 --data-xor=0xDEADBEAF          ; xor IP payload (after IP header) with 32-bit HEX value
 --data-xor-offset=<position>   ; start xoring at specified position after IP header end
 --data-xor-len=<bytes>         ; xor block max length. xor entire packet after offset if not specified
 --csum=none|fix|valid          ; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid

L’opération XOR étant symétrique, les mêmes paramètres sont définis pour l’obfuscateur et le désobfuscateur.
De chaque côté, une instance du programme est lancée.

Filtrer les paquets sortants est facile car ils sont ouverts. Cependant, une certaine quantité d'u32 est requise pour les messages entrants.
Le numéro de protocole ("-p") dans le filtre est le résultat du xor du protocole d'origine avec ipproto-xor.
server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16  -j NFQUEUE --queue-num 300 --queue-bypass

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j NFQUEUE --queue-num 300 --queue-bypass
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16  -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=128 --data-xor=0x458A2ECD --data-xor-offset=4 --data-xor-len=44

Pourquoi data-xor-offset = 4: les en-têtes de protocole TCP et UDP commencent par les numéros de port source et de destination, 2 octets chacun.
Pour faciliter l’écriture en u32, ne touchez pas les numéros de port. Vous pouvez toucher, mais alors vous devez comprendre dans quoi
les ports d’origine seront transformés et écriront ces valeurs en u32.
Pourquoi data-xor-len = 44: un exemple est donné pour wireguard. 44 octets suffisent pour XOR l’en-tête udp et tous les en-têtes Wireguard.
Viennent ensuite les données chiffrées de wireguard, cela n’a aucun sens de les XOR.

Vous pouvez même transformer udp en "tcp corbeille" avec ipproto-xor = 23. Selon l'en-tête ip, il s'agit de tcp, mais à la place de l'en-tête tcp, il est inutile.
D'une part, de tels paquets peuvent passer par des boîtes moyennes et conntrack peut devenir fou.
D'un autre côté, cela peut même être bon.

Il y a des nuances avec ipv6. Dans ipv6, il n'y a pas de concept de numéro de protocole. Mais il y a le concept de "prochain en-tête".
Comme dans ipv4, vous pouvez y écrire n'importe quoi. Mais dans la pratique, cela peut entraîner des messages ICMPv6 Type 4 - Problème de paramètre.
Pour éviter cela, vous pouvez convertir le protocole à la valeur 59. Cela signifie "pas d'en-tête suivant".
Pour obtenir le paramètre "ipproto-xor", le numéro de protocole original XOR avec 59.

udp: ipproto-xor = 17 ^ 59 = 42
tcp: ipproto-xor = 6 ^ 59 = 61

server ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "40&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --sport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

client ipv6 tcp:12345 :
ip6tables -t mangle -I PREROUTING -i eth0 -p 59 -m u32 --u32 "38&0xFFFF=12345" -j NFQUEUE --queue-num 300 --queue-bypass
ip6tables -t mangle -I POSTROUTING -o eth0 -p tcp --dport 12345 -j NFQUEUE --queue-num 300 --queue-bypass

ipobfs --qnum=300 --ipproto-xor=61 --data-xor=0x458A2ECD --data-xor-offset=4

FRAGMENTATION IP
Si l'hôte émetteur envoie un paquet trop long, il est fragmenté au niveau IP.
L'hôte destinataire réassemble uniquement les paquets adressés à l'hôte lui-même.
Dans la chaîne PREROUTING, les paquets sont encore fragmentés.
Lorsque vous n'appliquez la désobfuscation qu'à une partie du paquet, le cheksum devient inévitablement invalide.
csum = correctif ne aide pas.
Pour ipv4, l'ajout d'une règle à la chaîne INPUT au lieu de PREROUTING aide.
Bien sûr, seuls les paquets adressés à l'hôte lui-même sont capturés, mais ils viennent
dans NFQEUEUE à l’état déjà assemblé et correctement désobfusqué.
La fragmentation IP est indésirable, il convient de la combattre en définissant le MTU correct.
à l'intérieur du tunnel. Certains protocoles reposent sur la fragmentation ip. Ceux-ci incluent IKE (sans rfc7383).

FRAGMENTATION IPV6
La fragmentation est également possible dans ipv6; toutefois, elle n’est effectuée que par l’hôte expéditeur, généralement
udp et icmp lorsque le cadre ne rentre pas dans mtu. L'en-tête "44" est ajouté à tous les fragments immédiatement après l'en-tête ipv6.
Malheureusement, toutes les tentatives visant à capturer la trame complète reconstruite dans diverses tables ont échoué.
Seul le premier fragment est pris. Il n'était pas possible de trouver la raison. Est-ce un bug ou une fonctionnalité n'est connue que de Torvalds.

CHECKSUMS:
 Le travail avec les sommes de contrôle commence lorsqu'un paquet TCP ou UDP passe par l'obfuscateur.
Pour les paquets entrants, l'opération ipproto-xor est exécutée en premier, puis il est analysé s'il s'agit de tcp ou d'udp.
Pour sortant, le contraire est vrai.
--csum = none - ne touchez pas du tout les sommes de contrôle. si, après la somme de contrôle de désobfuscation, est invalide, le système éliminera le paquet.
--csum = fix - mode de contrôle de somme de contrôle. il n'est pas possible de désactiver la vérification de la somme de contrôle dans NFQUEUE.
Au lieu de cela, la somme de contrôle des paquets entrants est recalculée et remplacée afin que le système accepte le paquet.
--csum = valid - ramène la somme de contrôle à un état valide pour tous les paquets - entrant et sortant.
Ce mode est utile lorsque vous utilisez NAT qui bloque les paquets non valides.

Le recalcul de la somme de contrôle augmente l'utilisation du processeur.
Voir aussi la section "Pause NAT".


DESAVANTAGE:
Chaque paquet sera jeté dans nfqueue, donc la vitesse diminuera considérablement. 2-3 fois.
Si vous comparez wireguard + ipobfs à openvpn sur un routeur soho, openvpn sera toujours plus lent.


ipobfs_mod
-----------

Identique à ipobfs, mais implémenté en tant que module de noyau Linux. Cela donne une chute de performance de seulement 20%.
Il duplique la logique ipobfs et est compatible avec celle-ci.

Il est possible d'utiliser ipobfs sur peer1 et ipobfs_mod sur peer2, ils fonctionneront ensemble.
Cependant, par défaut, ipobfs_mod produira des paquets TCP et UDP avec des cheksums invalides, le système
avec ipobfs va les jeter. Utilisez csum = fix du côté ipobfs_mod.

Les commandes iptables sont les mêmes, mais au lieu de "-j NFQEUEUE", utilisez "-j MARK --set-xmark".
ipobfs_mod effectue un traitement de paquet basé sur fwmark.

Les paramètres sont transmis via les paramètres de module de noyau spécifiés dans la commande insmod.   

server ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 16 -j MARK --set-xmark 0x100/0x100

client ipv4 udp:16 :
iptables -t mangle -I PREROUTING -i eth0 -p 145 -m u32 --u32 "0>>22&0x3C@0>>16&0xFFFF=16" -j MARK --set-xmark 0x100/0x100
iptables -t mangle -I POSTROUTING -o eth0 -p udp --dport 16 -j MARK --set-xmark 0x100/0x100

rmmod ipobfs
insmod /lib/modules/`uname -r`/extra/ipobfs.ko  mark=0x100 ipp_xor=128 data_xor=0x458A2ECD data_xor_offset=4 data_xor_len=44

Le module prend en charge jusqu'à 32 profils. Les paramètres de chaque profil sont séparés par des virgules.
Par exemple, la commande suivante combine les fonctions de 2 gestionnaires NFQUEUE des exemples précédents:
insmod / lib / modules / `uname -r` / extra / ipobfs.ko mark = 0x100,0x200 ipp_xor = 128.61 data_xor = 0x458A2ECD, 0x458A2ECD data_xor_offset = 4.4 data_xor_len = 44.0
Il est possible d'utiliser différents profils pour les paquets entrants et sortants.
Cela perturbera encore davantage le DPI en réduisant la corrélation des flux entrants / sortants.
Si le paramètre 'markmask' est défini, le profil avec masque / masque de masque gagne, sinon le masque / masque est recherché.
Le paramètre markmask est unique pour tous les profils, pas besoin de virgules.
Utilisez markmask si les profils sont nombreux pour ne pas gaspiller un seul bit pour chacun.
Par exemple: 0x10 / 0xf0, 0x20 / 0xf0, ..., 0xf0 / 0xf0

Par défaut, le module établit un point d'ancrage sur les paquets entrants avec priorité mangle + 1, de sorte que la table mangle a déjà été traitée.
au moment de l'appel. Si des protocoles IP non standard arrivent à l'entrée, tout va bien. Mais s'il y a des paquets avec
le protocole de transport qui prend en charge checksumming, tel que tcp ou udp, puis modifie les paquets avec une somme de contrôle non valide
n'atteindra pas le crochet + 1 crochet. Le module ne les recevra pas.
Pour résoudre ce problème, spécifiez le paramètre pre = raw et faites: iptables -t raw -I PREROUTING ...
Les paquets sortants peuvent être traités de la manière habituelle par mangle.
Si vous devez utiliser des protocoles ipv4 fragmentés, remplacez iptables PREROUTING par INPUT (voir la remarque dans la section ipobfs),
spécifiez le paramètre de module "prehook = input".

Les paramètres pre, prehook, post, posthook sont définis individuellement pour chaque profil et doivent être séparés par une virgule.

Le module désactive la vérification et le calcul de la somme de contrôle au niveau du système d'exploitation pour tous les paquets traités, dans certains cas.
recalculer les sommes de contrôle TCP et UDP indépendamment.
Si le paramètre csum = none, le module ne calcule pas du tout la somme de contrôle, ce qui permet d'envoyer des paquets avec une somme de contrôle non valide.
avant obfuscation. Les paquets désobfusqués peuvent contenir une somme de contrôle non valide.
Si csum = fix, le module reprend le recalcul de la somme de contrôle sur les paquets sortants avant la modification de la charge utile,
répétant ainsi les fonctions du système d'exploitation ou du déchargement matériel. Sinon, le déchargement du système d'exploitation ou du matériel gâcherait 2 octets de données
et après le paquet de désobfuscation contiendrait la somme de contrôle incorrecte.
Si csum = valide, le recalcul de la somme de contrôle est effectué après la modification de la charge utile des paquets entrants et sortants.
Cela garantit la visibilité de la transmission des paquets avec une somme de contrôle valide.
La correction de somme de contrôle sur le paquet entrant est nécessaire si le périphérique avec ipobfs n’est pas le destinataire,
mais remplit la fonction de routeur (avant). Alors qu'il y a un paquet valide sur l'interface de sortie.
Le destinataire régulier n'acceptera pas les paquets dont la somme de contrôle est incorrecte.

Le paramètre debug = 1 active la sortie de débogage. Vous verrez ce qui est fait avec chaque paquet traité dans dmesg.
Il ne devrait être utilisé que pour le débogage. Avec un grand nombre de paquets, le système ralentira considérablement
en raison de la production excessive dans dmesg.

Vous pouvez afficher et modifier certains paramètres ipobfs sans recharger le module: / sys / module / ipobfs / parameters

MODULE COMPILING sur un système linux traditionnel:
Au début, installez les en-têtes du noyau. pour debian:
sudo apt-get install linux-headers .....
make
sudo make install
AVIS DE VITESSE
Si seul ipproto-xor est spécifié, le ralentissement est très proche de zéro.
Avec data-xor, il est préférable de ne pas xor compenser après 100-140 octets.
De cette façon, vous pouvez éviter de linéariser les skb et économiser beaucoup de temps processeur.
l'option debug = 1 peut indiquer si la linéarisation a lieu ou non.

ouvert
-------

Sur un système Linux x64, téléchargez et décompressez le SDK à partir de la version de votre micrologiciel pour votre appareil.
La version du SDK doit correspondre exactement à la version du microprogramme, sinon vous ne construirez pas de module de noyau approprié.
Si vous avez créé le micrologiciel vous-même, au lieu du SDK, vous pouvez et devriez utiliser cette version.
mise à jour des scripts / flux -a
scripts / flux installer -a
Copiez openwrt / * dans le dossier SDK, en préservant la structure de répertoires.
Copiez ipobfs et ipobfs_mod (code source) dans packages / ipobfs (celui-ci openwrt Makefile est).
À partir de la racine du SDK, exécutez: make package / ipobfs / compile V = 99
Recherchez 2 ipk: bin / packages /..../ ipobfs..ipk et bin / target /..../ kmod-ipobfs..ipk
Copiez la version sélectionnée sur le périphérique, installez-la via "opkg install ... ipk".
En cas de réinstallation, commencez par "opkg remove ipobfs" / "opkg remove kmod-ipobfs".

Pause NAT
------------

Dans le cas général, il est prudent de supposer que NAT ne peut que transmettre le trafic TCP, UDP, ICMP.
Certains NAT contiennent également des aides pour les protocoles spéciaux (GRE). Mais pas tous les NAT et pas sur tous les périphériques.
NAT peut passer des protocoles IP non standard, mais il n’a pas les moyens de suivre l’IP source qui a été initié.
communication. Si des protocoles non standard fonctionnent via NAT, ne travaillez que pour un seul périphérique derrière NAT.
L'utilisation d'un protocole IP avec plusieurs périphériques derrière NAT n'est pas possible. Il y aura un conflit.
Par conséquent, ipproto-xor peut être utilisé avec précaution.

Pensez au NAT basé sur Linux (presque tous les routeurs domestiques) sans aide.
Comme le montre l'étude, les champs d'en-tête de transport contenant la longueur de la charge utile et les indicateurs sont importants.
Par conséquent, le décalage xor-data-minimum pour tcp est de 14, pour udp de 6. Sinon, le paquet ne passera pas du tout à NAT.

Tout NAT suivra certainement les drapeaux TCP, car conntrack détermine le début de la connexion.
Conntrack est une partie vitale de tout NAT. Le champ d’indicateur décalé dans l’en-tête tcp est 13.

Linux conntrack par défaut vérifie les sommes de contrôle du protocole de transport et ne suit pas les paquets dont la somme de contrôle est invalide.
De tels paquets ne provoquent ni l'apparition ni le changement d'entrées dans la table conntrack, l'état des paquets est INVALID,
L'opération SNAT ne leur sera pas appliquée, néanmoins, la transmission de tels paquets aura toujours lieu inchangée,
maintenir l'adresse source du réseau interne. Pour éviter ce problème, les routeurs correctement configurés s'appliquent
des règles telles que "-m état - état INVALID -j DROP" ou "-m conntrack --ctstate INVALID -j DROP", interdisant ainsi le transfert
les paquets que conntrack a refusé de rendre compte.
Ce comportement peut être modifié avec la commande "sysctl -w net.netfilter.nf_conntrack_checksum = 0".
Dans ce cas, les sommes de contrôle ne seront pas prises en compte, conntrack acceptera les paquets même avec des cheksums invalides, NAT fonctionnera.
En openwrt, net.netfilter.nf_conntrack_checksum = 0 par défaut, afin que NAT fonctionne

cd ipobfs_mod

