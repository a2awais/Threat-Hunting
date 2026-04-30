// Malicious Browser Extensions from differene threat intel sources 

| "#event_simpleName" = InstalledBrowserExtension
| in(BrowserExtensionId, values=[

// https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2
obifanppcpchlehkjipahhphbcbjekfa, // Telegram Multi-account
mdcfennpfgkngnibjbpnpaafcjnhcjno, // Web Client for Telegram, // Teleside
mmecpiobcdbjkaijljohghhpfgngpjmk, // YouSide, // Youtube Sidebar
bfoofgelpmalhcmedaaeogahlmbkopfd, // Web Client for Youtube, // SideYou
cbfhnceafaenchbefokkngcbnejached, // Web Client for TikTok
ogogpebnagniggbnkbpjioobomdbmdcj, // Text Translation
ldmnhdllijbchflpbmnlgndfnlgmkgif, // Page Locker
lnajjhohknhgemncbaomjjjpmpdigedg, // Page Auto Refresh
aecccajigpipkpioaidignbgbeekglkd, // Web Client for Rugby Rush, // SideGame
akebbllmckjphjiojeioooidhnddnplj, // Formula Rush Racing Game
akifdnfipbeoonhoeabdicnlcdhghmpn, // Piggy Prizes, // Slot Machine
akkkopcadaalekbdgpdikhdablkgjagd, // Slot Arabian
alkfljfjkpiccfgbeocbbjjladigcleg, // Frogtastic
alllblhkgghelnejlggmmgjbkdabidie, // Black Beard Slot Machine
amkkjdjjgiiamenbopfpdmjcleecjjgg, // Indian, // Slot Machine
amnaljnjmgajgajelnplfmidgjgbjfhe, // Mahjong Deluxe
bbjdlbemjklojnbifkgameepcafflmem, // Crazy Freekick
bdnanfggeppmkfhkgmpojkhanoplkacc, // Slot Car Racing
bgdkbjcdecedfoejdfgeafdodjgfohno, // Clear Cache Plus
bnchgibgpgmlickioneccggfobljmhjc, // Galactica Delux, // Slot Machine
bpljfbcejldmgeoodnogeefaihjdgbam, // Speed Test for Chrome, // WiFi SpeedTest
cbnekafldflkmngbgmbnfmchjaelnhem, // Game SkySpeedster
cdpiopekjeonfjeocbfebemgocjciepp, // Master Chess
cehdkmmfadpplgchnbjgdngdcjmhlfcc, // Hockey Shootout
cljengcehefhflhoahaambmkknjekjib, // Odds Of The Gods, // Slot Machine
clpgopiimdjcilllcjncdkoeikkkcfbi, // Billiards Pro
cmeoegkmpbpcoabhlklbamfeidebgmdf, // Three Card Poker
cmlbghnlnbjkdgfjlegkbjmadpbmlgjb, // Donuts, // Slot Machine
cnibdhllkgidlgmaoanhkemjeklneolk, // Archer, // Slot Machine
cpnfioldnmhaihohppoaebillnambcgn, // Rugby Rush
dbohcpohlgnhgjmfkakoniiplglpfhcb, // Bingo
dcamdpfclondppklabgkfaofjccpioil, // Web Client for game Cricket Batter Challenge
dljlpildgknddpnahppkihgodokfjbnd, // Slot Machine Zeus Treasures
dlpiookhionidajbiopmaajeckifeehn, // Horse Racing
dmaibhbbpmdihedidicfeigilkbobcog, // Aztec, // Slot Machine
dohenclhhdfljpjlnpjnephpccbdgmmb, // Straight 4
dpdemambcedffmnkfmkephnhhnclmcio, // Slot The Gold Pot
ejlcbfmhjbkgohopdkijfgggbikgbacb, // American Roulette Royale
eljfpgehlncincemdmmnebmnlcmfamhm, // Asia Slot
enmmilgindjmffoljaojkcgloakmloen, // Web Client for game Drive Your Car
eoklnfefipnjfeknpmigmogeeepddcch, // Jurassic Giants, // Slot Machine
fddajeklkkggbnppabbhkdmnkdjindlo, // Street Basketball
fibgndhgobbaaekmnneapojgkcehaeac, // Tarot Side Panel
fjfhejmbhpabkacpoddjbcfandjoacmb, // Dragon Slayer, // Slot Machine
flkdjodmoefccepdihipjdlianmkmhgc, // Best Blackjack
fmajpchoiahphjiligpmghnhmabolhoh, // Book Of Magic, // Slot Machine
gaafhblhbnkekenogcjniofhbicchlke, // Snake, // Slot Machine
gbaoddbbpompjhmilbgiaapkkakldlpc, // Dice King, // Classic Craps And Roll Game
gbhhgipmedccnankkjchgcidiigmioio, // Slot Ramses
gfhcdakcnpahfdealajmhcapnhhablbp, // Battleship War
gipmochingljoikdjakkdolfcbphmlom, // Gold Miner 2
glofhphmolanicdaddgkmhfmjidjkaem, // Greyhound Racing, // Dog Race Simulator
haochenfmhglpholokliifmlpafilfdc, // Hercules: Sports Legend
hbobdcfpgonejphpemijgjddanoipbkj, // Flicking Soccer
hdmppejcahhppjhkncagagopecddokpi, // Voodoo Magic, // Slot Machine
heljkmdknlfhiecpknceodpbokeipigo, // Web Client for Hockey Shootout, // SideGame
hiofkndodabpioiheinoiojjobadpgmj, // MASTER CHECKERS
hkbihmjhjmehlocilifheeaeiljabenb, // Watercraft Rush
hlmdnedepbbihmbddepemmbkenbnoegd, // Car Rush
hmlnefhgicedcmebmkjdcogieefbaagl, // Video Poker Deuces Wild
hnpbijogiiaegambgpaenjbcbgaeimlf, // Slot Machine Ultimate Soccer
ibelidmkbnjmmpjgfibbdbkamgcbnjdm, // Christmas Eve, // Slot Machine
ihbkmfoadnfjgkpdmgcboiehapkiflme, // Columbus Voyage, // Slot Machine
ijccacgjefefdpglhclnbpfjlcbagafm, // High or Low Casino Game
ijfmkphjcogaealhjgijjfjlkpdhhojk, // Goalkeeper Challenge
ijpgccpmogehkjhdmomckpkfcpbjlmnj, // Tropical Beach, // Slot Machine
imjmnghlhiimodfkdkgnfplhlobehnpm, // BlackJack 3D
jddinhnhplibccfmniaakhffpjpnaglp, // Web Client for game Classic Bowling
jmopjanoebpdbopigcbpjhiigmjolikk, // Raging Zeus Mines
jnmmbmkmbkcccpihjgnhjmhhkokfdnfe, // Classic Backgammon
jodocbbdcdclkhjkibnlfhbmllcpfkfo, // Slot Machine The Fruits
kahcolfecjbejjjadhjafmihdnifonjf, // Baccarat
kblomapfkjidbbbdllmofkcakcenkmec, // Mini Golf World
kbmindomjiejdikjaagfdbdfpnlanobi, // Gold Rush, // Slot Machine
kbnkkecifeppobnemkielnpagifkobki, // Pirat Slot
kjnakdbpijigdbfepipnbafnhbcfdkga, // 40 Imperial Crown, // Slot Machine
kknakidneabpfgepadgpkibalcnabnnh, // 3D Soccer Slot Machine
klglejfbdeipgklgaepnodpjcnhaihkd, // Premium Horse Racing
kmiidcaojgeepjlccoalkdimgpfnbagj, // Tanks Game
lcijkepobdokkgmefebkiejhealgblle, // Caribbean Stud Poker
lefndgfmmbdklidbkeifpgclmpnhcilg, // Wild Buffalo, // Slot Machine
lfkknbmaifjomagejflmjklcmpadmmdg, // Aqua, // Slot Machine
ljbgkfbiifhpgpipepnfefijldolkhlm, // Game Crypto Merge
lmcpbhamfpbonaenickjclacodolkbdl, // Sherwood Forest, // Slot Machine
lmgenhmehbcolpikplhkoelmagdhoojn, // Web Client for game Fatboy Dream
maeccdadgnadblfddcmanhpofobhgfme, // Lone Star Jackpots, // Slot Machine
medkneifmjcpgmmibfppjpfjbkgbgebl, // Hidden Kitty Game
mheomooihiffmcgldolenemmplpgoahn, // Keno
mmbbjakjlpmndjlbhihlddgcdppblpka, // Jokers Bonanza, // Slot Machine
mmbkmjmlnhocfcnjmbchmflamalekbnb, // Penalty Kicks
nbgligggjfgkpphhghhjdoiefbimgooc, // Pai Gow Poker
ncpdkpcgmdhhnmcjgiiifdhefmekdcnf, // Metal Calculator
ndajcmifndknmkckdcdefkpgcodciggk, // Farm, // Slot Machine
nelbpdjegmhhgpfcjclhdmkcglimkjpp, // Rail Maze Puzzle
nkacmelgoeejhjgmmgflbcdhonpaplcg, // RED DOG CARD GAME
nmegibgeklckejdlfhoadhhbgcdjnojb, // Coin Miner 2
nodobilhjanebkafmpihkpoabiggnnfl, // Black Ninja, // Slot Machine
oanpifaoclmgmflmddlgkikfaggejobn, // Pyramid Solitaire
ocflhkadmmnlbieoiiekfcdcmjcfeahe, // Chrome Client for Downhill Ski, // SideGame
odeccdcabdffpebnfancpkepjeecempn, // Slot Machine Mr Chicken
oejhnncfanbaogjlbknmlgjpleachclf, // Web Client for French Roulette, // SideGame
ogbaedmbbmmipljceodeimlckohbnfan, // 3D Roulette Casino Game
ojkbafekojdcedacileemekjdfdpkbkf, // Slot Machine Space Adventure
pdgaknahllnfldmclpcllpieafkaibmf, // Whack 'em All
peflgkmfmoijonfgcjdlpnnfdegnlaji, // Video Poker Jacks or Better
phfkdailnomcbcknpdmokejhellbecjb, // Swimming Pro
pkghgkfjhjghinikeanecbgjehojfhdg, // InterAlt
pllkanemicadpcmkfodglahcocfdgkhj, // Gold of Egypt, // Slot Machine

// Threat Intel: https://www.ox.security/blog/malicious-chrome-extensions-steal-chatgpt-deepseek-conversations/
fnmihdojmnkclgjpcoonokmkhjpjechg, // (Chat GPT for Chrome with GPT-5, Claude Sonnet & DeepSeek AI)
inhcgfpbfdjbjogdfjbclgolkmhnooop, // (AI Sidebar with Deepseek, ChatGPT, Claude and more.)

// Threat Intel: https://www.koi.ai/blog/urban-vpn-browser-extension-ai-conversations-data-collection
eppiocemhmnlbhjplcgkofciiegomcon, // (Urban VPN Proxy)
almalgbpmcfpdaopimbdchdliminoign, // (Urban Browser Guard)
feflcgofneboehfdeebcfglbodaceghj, // (Urban Ad Blocker)
pphgdbgldlmicfdkhondlafkiomnelnk, // (1ClickVPN Proxy for Chrome)
nimlmejbmnecnaghgmbahmbaddhjbecg, // (Urban VPN Proxy)
jckkfbfmofganecnnpfndfjifnimpcel, // (Urban Browser Guard)
gcogpdjkkamgkakkjgeefgpcheonclca, // (Urban Ad Blocker)
deopfbighgnpgfmhjeccdifdmhcjckoe, // (1ClickVPN Proxy for Edge)

// Threat Intel: https://www.infosecurity-magazine.com/news/18-malicious-chrome-edge-extensions/
Kgmeffmlnkfnjpgmdndccklfigfhajen,
Dpdibkjjgbaadnnjhkmmnenkmbnhpobj,
Gaiceihehajjahakcglkhmdbbdclbnlf,
Mlgbkfnjdmaoldgagamcnommbbnhfnhf,
Eckokfcjbjbgjifpcbdmengnabecdakp,
Mgbhdehiapbjamfgekfpebmhmnmcmemg,
cbajickflblmpjodnjoldpiicfmecmif,
Pdbfcnhlobhoahcamoefbfodpmklgmjm,
Eokjikchkppnkdipbiggnmlkahcdkikp,
Ihbiedpeaicgipncdnnkikeehnjiddck,
Jjdajogomggcjifnjgkpghcijgkbcjdi,
Mmcnmppeeghenglmidpmjkaiamcacmgm,
Ojdkklpgpacpicaobnhankbalkkgaafp,
Lodeighbngipjjedfelnboplhgediclp,
Hkjagicdaogfgdifaklcgajmgefjllmd,
Gflkbgebojohihfnnplhbdakoipdbpdm,
Kpilmncnoafddjpnbhepaiilgkdcieaf,
caibdnkmpnjhjdfnomfhijhmebigcelo,

// Threat Intel: https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/
Mdaboflcmhejfihjcbmdiebgfchigjcf,
Gaoflciahikhligngeccdecgfjngejlh,
fedimamkpgiemhacbdhkkaihgofncola,
jlhgcomgldfapimdboelilfcipigkgik,
Jdjldbengpgdcfkljfdmakdgmfpneldd,
deljjimclpnhngmikaiiodgggdniaooh,
Giaoehhefkmchjbbdnahgeppblbdejmj,
Hmooaemjmediafeacjplpbpenjnpcneg,
Acbiaofoeebeinacmcknopaikmecdehl,
Nlgphodeccebbcnkgmokeegopgpnjfkc,
Fbcgkphadgmbalmlklhbdagcicajenei,
Alplpnakfeabeiebipdmaenpmbgknjce,
Ogcaehilgakehloljjmajoempaflmdci,
Onomjaelhagjjojbkcafidnepbfkpnee,
bpconcjcammlapcogcnnelfmaeghhagj,
gdocgbfmddcfnlnpmnghmjicjognhonm,

// Threat Intel: https://cybersecuritynews.com/35-google-chrome-extensions-hacked/
nnpnnpemnckcfdebeekibpiijlicmpom,
kkodiihpgodmdankclfibbiphjkfdenh,
oaikpkmjciadfpddlpjjdapglcihgdle,
dpggmcodlahmljkhlmpgpdcffdaoccni,
acmfnomgphggonodopogfbmkneepfgnh,
mnhffkhmpnefgklngfmlndmkimimbphc,
cedgndijpacnfbdggppddacngjfdkaca,
bbdnohkpnbkdkmnkddobeafboooinpla,
egmennebgadmncfjafcemlecimkepcle,
bibjgkidgpfbblifamdlkdlhgihmfohh,
befflofjcniongenjmbkgkoljhgliihe,
pkgciiiancapdlpcbppfkmeaieppikkk,
llimhhconnjiflfimocjggfjdlmlhblm,
oeiomhmbaapihbilkfkhmlajkeegnjhe,
ekpkdmohpdnebfedjjfklhpefgpgaaji,
epikoohpebngmakjinphfiagogjcnddm,
miglaibdlgminlepgeifekifakochlka,
eanofdhdfbcalhflpbdipkjjkoimeeod,
ogbhbgkiojdollpjbhbamafmedkeockb,
bgejafhieobnfpjlpcjjggoboebonfcg,
igbodamhgjohafcenbcljfegbipdfjpk,
mbindhfolmpijhodmgkloeeppmkhpmhc,
hodiladlefdpcbemnbbcpclbmknkiaem,
pajkjnmeojmbapicmbpliphjmcekeaac,
ndlbedplllcgconngcnfmkadhokfaaln,
epdjhgbipjpbbhoccdeipghoihibnfja,
cplhlgabfijoiabgkigdafklbhhdkahj,
jiofmdifioeejeilfkpegipdjiopiekl,
hihblcmlaaademjlakdpicchbjnnnkbo,
lbneaaedflankmgmfbmaplggbmjjmbae,
eaijffijbobmnonfhilihbejadplhddo,
hmiaoahjllhfgebflooeeefeiafpkfde,

// Threat Intel: https://www.koi.ai/blog/vk-styles-500k-users-infected-by-chrome-extensions-that-hijack-vkontakte-accounts
"ceibjdigmfbbgcpkkdpmjokkokklodmc",
"mflibpdjoodmoppignjhciadahapkoch",
"lgakkahjfibfgmacigibnhcgepajgfdb",
"bndkfmmbidllaiccmpnbdonijmicaafn",
"pcdgkgbadeggbnodegejccjffnoakcoh"
])

| groupBy([ComputerName, UserName, BrowserExtensionId, BrowserProfileName, BrowserExtensionName, BrowserExtensionRequestedPermissions, BrowserFilePath])
