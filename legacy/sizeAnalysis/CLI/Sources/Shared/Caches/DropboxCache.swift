//
//  File.swift
//
//
//  Created by Noah Martin on 9/29/21.
//

import Foundation

let dropboxCache = try! JSONDecoder().decode(
  CachedOptimizedMediaResults.self,
  from: dropboxCacheData.data(using: .utf8)!
)

let dropboxCacheData = """
  {
    "appId" : "com.dropbox.DropboxTest",
    "optimizedAudio" : [

    ],
    "optimizedImages" : [
      {
        "hash" : "8ad8d88f14a52a615b095afaa7665319abeeab2bf6ed534cdc09d43d3bd64c64",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "505818415916219717317825225113805324949461472031054813984242146721021586133192178",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "93ca3b7ade1e216e3f8ba6ca70171eabc382a4d48c182d1073608caa831d0220",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "202223838832419517614627811552551461471556702231351369116222424011597314836248158",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16820941481142085914561673714995101204157191170302412416516191582392283571995144",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "151241110191154967220980157242167226184109161561621928615552199187220194352268015213231",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "129252711419856193211204161245422241841561325165351831002062331651205195286177204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "73951952192441279769705918254792632111821326771189127163127180184255183114226255",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20524212611511019514767191531771412917150715713891032389311718621882152461541810632",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18675167911955322252211638824558143474219819854117821811268221118866016622750153",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "86197125171169222791961931497836232220614180126182244124822210195189169702033720235",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6b4ff9fe47df4c62f31e46d406c9d97c7296b47213fea60d7d05ec7538d0cc75",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "140176199522326820012119752151246851351881123020891857214643138574348239231104213234",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e888da02b7dd5d9fd01bcc6f7a49a5b6c5e23677d55202f3986f0b758df176b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "acbea2124fa46daef1cc1909063da6eb57dc7719200879f2f98429d87943d536",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22491102418354177122157130736916028241341955849233621010715702411667725514526127",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cf1c57e6461de06cf38a43fd631793d05710ce5b611a51c7b787e96133bfbe6c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c9064650fdfa58a831ec4602dbb0d35350031ccbb7f734e613c0feae353f913f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3198401443212416021717194075470751197658160223162558084254322511610813148165",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16223214793318154247292184616511641348017021794136218756117215592271867824219656",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1761482112925312023458824824219224015814812816289210188520013968241154325454136127",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "243147193120195148252242524913422913020324910569193124131688169219108696197181063951",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14824624310610321013417713745923896751472065615920220172154103204197865627132164103247",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24d1063ab39c8a9c6095c7813ea2df35b6e0c9982ef1d2beb1fd0ca8157bd631",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "812312101772101702251696499113156116131110571871951811013522323412041681381723016619910",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "85f20edbba49912db62bf8ed72879a7b8d0eab1c2ffb3be096182ac0895a1721",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1261385650115205129236219213341219220360148194725068362222012121233612561180118130223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "787c900495dd1cc27cf883847e8e861af0a7262ad41739c784a82255ec9fcbcd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d32ed93ce98cd9f990736e405dea3895d2a0defe1872828333dd50fa24f7572c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "be0b45c8bb9ace3ca2a5d4fd441f32cde9fa19650f6846bf10922d80bc3c784f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "521156171152242109233203158481887417493179543383892136544201248418556818616281",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9794c8189df365aedd3e7e6915edd21cfd6c3a64ca528eab2342401ab61329d6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "671214114944230472422391319914145023029156198122152231232181502381631661038485224187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fb6b0bc7ff740a07357b0fca426dc58448f6b63e6195c8131313eabf9120a264",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bacb88dadbec179531feba4f5858d6293d38d4b59c7008efa714041fb7b689a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "73ce112efb4ab00665bc6a6359f25539f4a67259fb7a6cb8cb6deb1ddaf6d9f1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21547133183198411641821891671741719610118419122930492618421968112171682101741252610932",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "efdc4af7a3119cd97a57b254416bb4aeb84c6b6ba8deff86a98ef644fa1889ae",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "131201011122317418020723624253144206211718714434841131133144187244208167181833064",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "126100105207197207306211697130186331902392283181151481681408352123127492142229185118",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "af8b2c51fe58134c7dac3a5e29b33359161f6a4b4eff6f88ac423c4f4a6451d6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b0951ed71e06212e4df36da67af80f170e4cf8c5f7ce7ec5654a77ccd8faa727",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5a7b8c756545c9ff24ed9fb87b98262c32b466910b2edabcf9175a3c61231d58",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "141145156961763692188148147144150143201221881711952165184199124145416019217189161108143",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "89d2077636808ff2058d40bddf6c805fe995cb33d90d8d0daf4372b2fd3942ae",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "341652251143156353814163190752167971831752462379620118519210018319167207291320158",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "58632371121151425517821618811314251523168102145230871602097155147114491101439324915",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19139219612041921042315222180136681972461562417922711510812521581332095351266223218",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1c874140f2fccc696f2ae16b8dad980861244646c1db6e12aa36c2615f936c2c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22711757124591511231031541453218191115113217020323493229511426221731821132715912180",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "311214521822516231181271215116132101313714613210822119913412910813202101117109229597",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "58ead9ebb5322f27d4ca3f3da3040c690062b02ad91a3cf8cf5921b55e33e3d5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "28561331321982272021691524668179158912593691683616296891352081211671984410162",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0e35a599d862e240a7e537aa57f098a32e3c83ea804853777654c09e9b63bf73",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "326919532e51c2a7562a84fd61fca1f6b256e6827489e58d9582eac59b5f3167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8630cba481a6646d9c1f50d8e57b4474ff748286b745a0f4a2b0431b1bbbe497",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3bf81b17acdedbde3a7b5329861aa7f0b80e9de89524f71af6ad1cf70104918c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "472502172124010111548631501391622314611016911361202021823462121207230178310115336",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9c6008c64789c08de19781677981d30be97ee433e65167f78556a1cdc06269cc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1739197211605090101561882142305511813224184133135225149111127219251810108322392139",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9823926248125120143551151221318817112425212113869412291801712331231599211317231187171",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "90975bec7187cd37f2cfb72156d85175b2859cc73e1d3d2b72f4ba3de3f9041d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17586dca510bd6d4193e39eab3876fdfeae51115ad6a2a14983a3ffe39ceba7e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "200ddf488c70c017e0915bd5b053b593185119b1ebfb99e378b75911a39b6e57",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1801971365216226411211225225266231197471416135110222217208177199511526111019126236",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "701974159184122134180632072121272522539209160149571711361581931031822091211802481042471",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "116771127190131201959118729872451351618137240422014823815021891624518410115511163",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "50168792051324827152521878365731221819911826211218601071172349547281361012465472",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0758ed2337d3cbcc094c69ee662719ca4b56d94ac972dcc2a80353d82fc0dd05",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "822292001931611316621532239102243752001741771001872443220132250216339733841406138100",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "731631872431961611551392017521623978482152361411195250150169124822513169195180461049",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1051591991025010710724617110111112858144150181169422003515813717173251149220244151142247244",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e7bd68bc11c3ba3e0004754b867f486afa1a1b3614aa349879b7ee0928d2412",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "46a1803572a8802ae640bc70ae04aacf89043c7b5c3e2fcd0463a8572a1638ea",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb779e1b138945657628c6da7f3341b3f61654734d923357d2855ddc2c2de27d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2031611212642661632136125551251492531082297711724224217018125023396135196911712957",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2127118101231704511180230761184237176190171212139202302202331404180163206222230140191",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53b84122fa8475fc8e5e6f1db84d8d75e56deea2c0c85a425760915e632e95c2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1f4099dd4e9eb850f67d6b55a953913289b9c0f1f31107f0c6715dc365fb685a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1025181115637210049637224564324311811318522722927128218177091141177769104229",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fcfe3a80efc0a3708dba05270844ca1316ae777d14cdc23bfb590f55bba14e60",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "46d6e022f73c13dc277179af063f6a4be2f5b71ee1344ba90c0556bf254aafbd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "88538826af04672935eb914864dd987590c91d7138265f3637be5494b6710bf5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "932001757723813395242381902321231951922304249661083810719515322112347924555232243",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0b47c9e83f639c01333db4bba1cf10898ce416aa67533f70e8f42eca2b1ca1ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "49d35c4678b4c9dc65bb091b8243602e00afc984b0b245648cde81f84ede3628",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22920745160128143522471322341694873721073173112117227621157316121624715377108232240",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1092471872387760271133515325112417017011115615412218820519561991511502357180195108142",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "193012431371863020695671202025124711235119671003921518611105172651861988620615209",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5014915729684356121152292048782531751402021001406013410669497573010615110456227",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "717486537d98d6078ccfae353ea1d24dba8386dba14c761acf11c30455527fbb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e52214b4ce1706183a4e3121d8e1cbd2d8e4071a4ed86f81bce18459e1c66e2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "132133198210144101691098918716511611212821277311841512712398867211137952525387120118",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "131194244171492282411781592122511361984714124621015824723881907194872649117216151",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "90ab37810245da65ae7f607bf7df28bc9488a36d3db0f77646f0b4e08b50d026",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "62557ae0cce1a6271d1bf728389457f0964e45282f2e10be7b9911db03fe297f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ad0b9f67568f55910d9f812ffe51631540c8fce67cde33597cdab747a7f163a7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "919c9560391e882ed7361f417c7e64225f78d92cc91a67d1bda1b32ae494f2a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9016075244947234156171200215255246922189211881671377992723151149913094154168233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1951161821831601171271811778653867253145126182011499136881765321414023920345143",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0689899b6e40eecd892d1b9c7a9d4e730ff69fe4362567c33efcd1f658d6df65",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d37de5909cc5951f3d940b78f12276fb298f5a324b403fded545247d0d8ff7af",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "75191216316545195192272201212201471314314864148113742102011734484115184209537548220",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "469c8f4233342900a04afd3efdbc8bde393ae57bbe7c8ff39d2aca1c6ef4ebfe",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cab22111a6069106d976e4156941c751de2fc146eb422f12e4bfda247db75556",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "583d08009c8ebae3383907de80161b137737a90c86405ed5bc0aba50e9c4ad3c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "40198121031741048236961252481182416535193232103197248239661582281152512827755224201",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7260899befdf13f240548aaed99056da139fbedae874ff1445936fcfe8e98774",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "177413324618017423171643322519018899212561192476867176171155145253643157114281159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b7ad5828df677b3246eff7b391c5d78001a4171cb938a9d6eff9929d1b8f0654",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8c40f7b625cab2cdc6bc2c732d82c7e8fda61ef57e207ff679d1f5a01ee7c914",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "04a36b17847b7ce3122d1d635e120b56f5833ca67273c0aa839a13f97ff973f2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "203932022391201018121212058162301521811701009877182195519724974791894614324419338",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "931ac318e1bbe45e76ea132320ae4a05d1087c65f372da9aec6fbf390aa4ea86",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1512112131261081536512791180775724211041147991411820413825365502171041121019070198184",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5e23a3d71dcfe768d117867becc10ee378579937ac49743b9b38679cc7a0e183",
        "optimizeResults" : {
          "modernFormatSavings" : 27437,
          "inFormatSavings" : 29297
        }
      },
      {
        "hash" : "1f776676d6c913a074e21672ce0cfd73fb01815717d60881efbcd050559d87f5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8c196ad7da603e31ae53c0041e8ca1f657c5c5be96956304534ae0bdf770c3c1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a4bf7e94aae8a3dc9b1aa8239e8f716244ac806ffb2365063b90b1d0935b725c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "193229781862341221722414215850933818663167718423611313924614411402969127219145154131",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3023c057f9f154ed8cab5836a4f6e20653eeb7a3302e77a86ea3c04a38412f90",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "11817616724719619910820677238141311402557218281323994915512120922215223632152206090",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "849820220779191198552262615065223201892462241461711728021240802372066312387224197247",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2521168382241111322192291358632062775854512810795183102492182349111961351154",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "116237235139223184192101161916320914513239912214086918910110151816914360255321",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "63222159571642081213213120123511318647118181202150158213113810024325415919624491241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b8b48867f887b77090b0e307ac681d7d67c09f83d3c58c26c891ea68805888c8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "562382411221782251501232291912496625386576031692372021871201257113141135409020824249",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "59e0f57a17502a76e2730ead46421ba1d1f38b4dee630f0971027bcb1c20b57d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "41ccd7461edc388f11b9b09e2dffe225fd17ae3dc6c8d809d8c5329d2a0bc6bd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9c5342967895963b3e5e95aa57545e700bfedac0f62ef73acc4f6ce2bb805188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5461e11f1812baaa5fc06fab65e840b5e3ee7a16ae8ec6c6d4d23fd67b831500",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "29252199205217102237248157942817892511686090103239111010562251182671174021718929",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e950ae082ba0b649e063154a2fda0b3c6d91f3ad9cd9def2300747eecf4a6e71",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "56f6b737ab6b9bd52344246205b63b5c061930d17bcba4810d38069511693fde",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f0b376dc53992eaf95820e15823fe3b228a88b14bffa26ac3f945d05b7ac0632",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "123a5132655f5d8bec23925f4c4b237eb553b7fe773e7054611e2c53adca4de2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cd18cabba832fa3cf0c6b6e4c8f6b1832c344d2b2151d0cf87b3355e7dee97fd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "203254104170238170140132413783221195234915920811826201201229200459760651433914811620",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "205ac117f053730003997a8748d4efad6adae551c722e66ac100d6c7259c678a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b5551c16ddaa0172e32ebc8890aa0cdbf8a0eb29c7eb648767955ab3643fa2cb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "670c30ccb63032d404e3dfce5ff750c24636ac2f50a79f2a289c8694612cba1c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b8a06c013b2abfb843dcb9f5150fdd26fd2752a35416cd8dcea7b05d19af9438",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53251198227412012559291035645189214712501671681672873199135101108247712019683210",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb457c12721eba78eb1edd81c2252baf4f6a108f2a7ece14833a02cd4d54a1a1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2462271477324944236126961033172244682501921022262231054025122209682215371061344",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f306e7c20587ecbb19213f1e0f6feff92c1047bbb884cfdfc56e8485784bb1cb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9801f552a52e7733d29e1dbce0892cdf3f57106b1b5f0bd65255b7e7dbbf732c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e38fb2ca0bf151c50fb9e3c69e0df483159ef88759f8873a2323c65cf148ca61",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2126e23761436773ed40b5bc20c0c7c5f720744debbe8c3d93772aacd889bbeb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "412184885204193113552351322035914302235111156781092361294158126117146112541641248",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1038120019192018516785522258120551206517921316016421411215118134529315343120116200",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9ee075858e8148c8f4459bcdf271c0f9939e48d8467251a3aa06c45f83090a27",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "143179652718214012435132236117391021852361711612221081403121924922925411937721618535",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5b0ce4cd3f8ca24ecfb7e621cfa6ed842317d30bb85342a7d05647044272c009",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c00ce58928c53f9e80e123968841c48f2ec5f00bd23dfaffb47a05e36c6956a3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ec5579cef10b0a1f479c49c800382eb72bd58e26b5c7dcd74da0a9ff7fbe90d6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "118661322268122282377225111363848782532389845661362309151241957617892177",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e98d3eff890ff86c5c763d27f210c801a24e627b7a598e2e1c58d8d02cd01d65",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "116208192156401937729155591424889199334516718911015824313416120152209190132142919711",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "61168146155169210161121272291822091415970142141826076474822618716841781501102366189",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b40128977bf1d4ef082fac4e43052e4035e95074a7835dc42f7351469163d20f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3dcfd5a7ec06535e1f447cfb107353f3a0a33930b3c2517ec7b554d2b5e8c785",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "152155177951812511662239212224160158159154442001363144131181167175223510622314724166244",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "54a838ada22f6851e48eed726f013363bc3715cc9b5c5c15ee83e20fd2de43aa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fd2c958fafbd72662e6926b2de6b9de421da1f3988436b577de6829f48e4ace9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "378d19e5091b3b0676ff5b882cfbb609d2499cae97328415adb2dd21210a7d8b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2371417222919473176150248221121224412122241324924343281484806611220626661121681",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "58f559a74a232536a493d12a8940819cea8a0fa257e0756b855275ccf771720b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "186243248191124232232111230180222131169441461184110457181157149203161691681389127173",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2421981251781241592301675226212211465557131716512214417818013145129203253177176185162",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1511971282980168239174253103584813010816125147362081812365839241160165951741161745968",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "187932289065551810714982816155871147416738217110898157122230311718244227141204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18512614198245302473011420491649817923718811219182036119725320211416815993240117114",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6305d2d27e5bb9465422505d5e21640a706433bc3b62dd8455052ad03cf780ed",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b076f56fa2d5cf47722cc57d14761eda809bf8c0efdd1770e5875bc72c4ea269",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6dd92ef7c1368ff97bc09f99f1c370abbb1bc19c64926feb77e66605d36fb5a3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4b9cc07d2cfcd5eb5f51de15d9619df2cc959ba7e9c7bf4d6a5aa9679a6714eb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5b72e5d8a7efec2ada1704530ab5717829b593dcc6ccace713bd0631a067caee",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bc01c47ab3ac0eeeb3f7ab070e80c6e2dd759998b142165d3040d585ed35df66",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b038d56ced9ac9fb5bda15f565addace96b4de9522d0541bb1f651bb2e85f776",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cde9669bd38d01191a3dff02b642e06aee370a7a80f7a4c112611c4a0ba7f0ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b8d05942ca3ff591f3007a4e4c0352503e234413382f5a696769c8a156d5b637",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ff2f6cad29d7314413a625826db4377ac57955d87b6e0d56c9a3935f2fa0f9d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4fdce65a00dc8b62320b49b1aabe783b233a23547149c0d306d0603bfb46fc06",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4614cbe5c0fedd7251de305f3775214be28f3562adcb1a2a3fd1bdda22eef610",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a4ec0f14d776a928d091e4502eeb3f53d3c9a67cf18a0463553a33e739df099e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6421581702292141862071823421473235164381739025112210013016019170226185139211981910343",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f18a3d71f023ba6f31e209a74c496c76452726fbab1fcaadc9c417b59388d50a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "13123143205182143821212329235186148245023217123598910925315437126154164558118181211",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2241392039842255142514715533215971809141125204241126223316224153102200122113207",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8bdc33a81b3c9fe9d2f67ff9f45f02a28911561069bc60ffc07d23bac873ab3b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "eda0974c4f1006a072e27c8da89763362a95278056ae38a4cd875c03c054c760",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1fcac2f9c5c77fc37c614425c6f190baab41343b1fc3880ce7490f7c13057bd1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "292272482821781182141244225142230708312197187346154146191921824212912615319861112",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6ca5c4bd76636ee055dfa585bac2f5fdffae2cd419eb93d7e09a8067604a40ab",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "968dbc907436c206625397d136b9151ebe5c88a92682d2ea0f57008acd1a40fe",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "262341002482501301615630539511719014613610014311594967118283923424371247119019141",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "272723819414518839139207227158962079023758211823510810466313421140233253999312713",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b2ad4640c3d472aa3b5d273a15984c6fb490f580b02557b99493cd68a3b53840",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10380245161472161707271932211122522041431731195521216817205159113807652677118497180",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "957811319701146416414015320786204100214152137241146225221231931112172468220630189234135",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c8a1be892504d557e23723021378e5502287e0710081cb467f81304a4c102062",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "97c627bfd25acfbf05f247632ad69b358d5e8d0e3826d8e04b9a5e25e010fec8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d791c79a08fe54b056664489f72979176649ac74523424c5c3322facadc0db83",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "181732109518813226243201084218622410564632223393237201117684561721505941222",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "588065239172155195227911101631981152456923572221391364017623322213953011151227207",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "42e660f6d8c8932555311088acfa9deac446d0164644ab64bc1a62ab22a8dd92",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53fd5b03c3addc840a56d536bef51ee3c60bd2e40fdd1d38cbe81c1da9ea8fe0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1782117415315032979461878729774391722373862176025346187125175157371131131",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "83883de281a953f6e40f6e02e0aa65ff8d1e9eda3858eff0bd7e0c988e2272de",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "932379319253178302121911868522410323110922923515813101102153211522182112720719718217112",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "207141201372422342092339483502074917197108214172423010642514024460204179231183",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "133a82ec569589ea9a3ae8c871c7823c5ce4810988fd377bd2c90477e4d96b24",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8ca15cdf716d5a8e2a617d1ed471ce00299de2ab0321378bea49ed56420e2ee9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14214724121512229138112126177255193463223746195166246104492481192166610847301851369424",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "28d16ca8ca17d7e2e467884d81d826c2901e11cb12a3b2fa82d693089cdff257",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8310712428136191193187200182282381564114619203124367517622529614229174361377514111",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18415523512622817825269236775153125215240465754826432215115671513852472526418137",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1091792211331341171941941731771202251658125217924159113244262911310623714813228211248245187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fd50f74c3f7e382801231a52eb9c115280f5012c6f105734ad8ad51ebbb5e865",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23119751862401929621225151113240130101851671069111310695889186851141171411486123152",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1532161462113619792412281352452501718812211014516348164777159189192386481119915045",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ea513ee4f3d78dbc57e655ff0b7f3157d4178da163e30c847e69d8022fbea2e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3320912341266923817325117369222072131981474660976088244164249528191931915112997",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2511551941822111492577104010122422811216416221111258109112149246166136912381911421333521",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "230156232181223891685913314274240169375241191591026419125151244956023221024252736",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8165317f5e07ae847d0a1d0c39a92195ca472e9b4efc4d1aefc1bcea66cf4de4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1517413018184915191792820715789214292139249464018534212933887175941968",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4c94aea81feb8b076f491c424ef6e461ad7dd695125edfac76d1770d763e1e56",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71508893632fba7916f01ba5c8ec71b3063cbce0eb6b5687722892cb70235b67",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a4f0e5197b3da6dbe927bd3a2599cf80c10c5acc3d09a94b0c26c881d531dea0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e15616b94c058ad8a4ccf4fddee70c592960ccef722571732172b8c3ec5d6b66",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7ff73b8a28d0d89669fa63a245b4116de1123362a834cd04e58da006a32d02cb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ac56ec457e50cd711283e596accb45cc717758ba22b1e3f69a9c790ed1cebe4a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "193414096210135146134178253197417718334149871272351641842184301512269216922367156101",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "351238dbb5ab895fb977d6acc2749978656deb00271c57b3dc8bfdc9728577b3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2072558019924720434253371435023023613314416963131249189723281942117378211235663233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1651103613918812695721608521102233914512446394514942146682361431481792028998140232",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12147252541951871181023410518423152161871762221202261791712021168149140253131039355195",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c13e7c1163a83a50ca658a482314aa103551018769ee256ffe1eee74b318b1a9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20311433701312372402211881081191362381824923126169691526723015366112332111016520238162",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1261652132339514868020211718416321612217776251173233230201175124151222162153232391385",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9724232243183167216775213217151356607157138720916520147220122241777318585127104",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "36aa7a3fb2a353458692890e46d08c9a4e4174f5b92596e7da55decc37643c76",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "972bf13d6f453e27226b9e3c2891c9139b5136167fcdeaec41c13c3fce43bfe1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21061175240186165213711223621624264147701801931351042042369125587233881101979779645",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c252f4ed04f856a25227412f02ecc106d243cb2eb297e34b4b8436bbeb355a36",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7d8d86aae8aa516d541202610a6f003b5b85452721de0a226337c746e69d5daa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24901691313168187292326242198250216179642542121402352151211161381249493581135184",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "431217238148221150611612401711962138325014212661011951211561301539174233194198217141",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1543610222224206652219615312496118134227203124120171441241842482542351813125313228144217",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10121059105127161488254106623557176432186751244116018521313321317710419812715132204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f60a5ff4558233bc1ec03a13cda7fdd8ee62ddd291b97a02e0a41bea836ca063",
        "optimizeResults" : {
          "modernFormatSavings" : 11366,
          "inFormatSavings" : 25404
        }
      },
      {
        "hash" : "7f92912316fa5962fe3aae2ea94d72fc128509684bb4c32aed18b87178c9c226",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b27d48ba29e18d6e3e016abded1a0895901fc5d09fc39905fba82df6459e4950",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "137148197102214155240238114136244175992137772432432024723014016622252212122392103724766",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2261398666227242482332161843612255472432263881602481993821416516220810137131634741",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1551331310901206879200226622723421140107887234672522141461771174022614822243127179",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12591032161759537151123144137312616813225202321931622120242113109252762526915754",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "232331114347598719789169542257917516414923215924116114597542388624397192243225102194",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8dcac96da09edab8edf5de6b162dc885ab8a50777f1f15f4afeaee9a9ab21591",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a95bf823fd9a72fb7594c7dde753f1d998663b4b14d9bac0720fa58a3e6beee8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "145101401140162146206371132312321572721363013921026217107140551882197419511416310845",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9218317512618216717551206311461604218621016524322112322954183919759196241129254925174",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7618ddaaa9582a36a32d3a59b866d59b176748a353778542a75b996abaec0e1a",
        "optimizeResults" : {
          "modernFormatSavings" : 20844,
          "inFormatSavings" : 34983
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/upgrade-folder@3x.png"
      },
      {
        "hash" : "1761076315810012180618614788255109772109315101288624321129368415116623313985182156",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "186107155229154151111436312246147233216812401141621389071113742481105717718652160230",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14386201228452432761226751142491271551931883806223822921012811521519310119130116105139",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "160443661577913412133832194101711701047151526212295215141801238701388052",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ff4bbf697f6ff761f4874dae934a60f4fe8ac8fd8ae93cf116215632ac8c475d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6263deaab80d1cd702fb265413755fd64725810ec5c2e6daba88787e21dfc0d1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "181132572244109178123112551811079271308368488310911322919613119166913982618370",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2331101297414822914720032190164214156541941621831903918091174222931271311863137810652",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "678412489884782095162159197502393322318895105200143171174816198818518237204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f2c19c58eae8d585d8d424f0d4cfec41d21755385bbdb455f9f92ef9977efde0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ebfcfac97e3691ac32289457dfa25643798ef12c9f5dcb0122348320204c40ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "108255206188984139222641355711513716718720923215963166321502468094178386421661224216",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "361626976132122378422217115312223319861861351110859153137521291561541357416871224",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f42f51ff4e6fdeab511b3dd5fef2e943935f9073e1f8b1828138c3c08b624771",
        "optimizeResults" : {
          "modernFormatSavings" : 54673,
          "inFormatSavings" : 60804
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/previews-error-file-too-big@3x.png"
      },
      {
        "hash" : "f214ab4bd30fcdbaedb5c987b0e9972a9a7907365e43adee733682ec08951329",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b1d6010d745767fb39316348e806766937a15346115e9dde1e5523b3ad32cc2d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20220956132141457851159320611156108139142289288103431731761691738215114018978160217",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "141281318014588100492620117612213216012131177160527117821169271502221441479426176",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "98fd0a967f929f81e4a8c2e9544d97d597861a6b769ebeb5f93898ebee9fafcd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2032461221061331722442516215197717313067243192181155189902014443512132999852063759",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23211221723810343170132208772072218319915514524924050219100519193124821621411792317",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20ee465b357bd1ac4c72b42167db7e66dbd14e7ec1dcf47234a28a53d569ce73",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "929d03ab01425d818402a296ab70be6a9b0bf5743080dfcda00bace9e241b90e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a220c592c38639d71ee090eb06b86bef0e22a710659dce9979726018d93e696b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "225311088093149247111172302316786361031022525312110674186911172419517020722823018887",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "49320853161122168282498922825315275208752149023712863409090192151521111989750",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14794183212424424970417524052057154752311919812237150782001192530937589147",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "120139815518931451588223915562062091014028136224941252421431791162141899885423223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2498121561024161957918559252205192230166508780521102342092321841101081252086122837",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bf413157836371346353eab1e53fc999652edab2906d6f500ddcb0b7b756b4ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e41c94657f3273bb494f0bd00cd448e70e43bcaeb7a45a999a06f47073f5346c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8063250114244240238212931852555412012112535188178198652482421761762032111762551255227",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1049514513423018223249140106791515611217118116714513723223112187249108103110708333172252",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1276892128295583229114631444971111321401291521051932182818914719221924847348197",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2b6d35724a089ed55e028ca462d71c5d2ad9189ed336effc8b13be97bbe2a233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0b6033a6cc176e40022a05a52e2c754956bbe6113f059d4ede1b2f055b3b4199",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2441107012555910521211961361771151232447115883601497519115413516971214821622562188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1742a2c5519b50ccb7e6a9fc2c9cfb281b940ecafcffaf2e2384ee04293d7f9e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5b4c0e4dee8ed9f19a5abd7f202f342c44f33be281370d67fce28f1756b27a12",
        "optimizeResults" : {
          "modernFormatSavings" : 7348,
          "inFormatSavings" : 20956
        }
      },
      {
        "hash" : "116803722380203111154521362472154077112225133964419242131198109167742061561391771847",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e5fd202a783d6ff7b9adb767d2e9a7abd0451c3784c5736a786c80c373901e82",
        "optimizeResults" : {
          "modernFormatSavings" : 46512,
          "inFormatSavings" : 54916
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/illo-blankslate-photos@3x.png"
      },
      {
        "hash" : "136214366103110150621152161601892229474142362318550791911572051971871641791790202",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12bc669bcd823f6193cb80a776fe375479208d5d827b46a22dc44c8d7f7cb56e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2301331849949158179250252636115081226232351441771772131361422316401121855511421894246",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "25131961561041278351632262161871358626208167106244233158223152152320224625198238",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a3e658fc8e681e3a17ba744b97daf2ea0e52f56b30a40153ec4c55fc520cce80",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6224574148918116119915821167135275111971961412169022019521824719040232189555443177",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "550cdc691b03d3f7165ece1af89456e2f5fa25d7219a8b545353a3f540cab405",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8d2f829f232f4cc6125398050107e3d87482cd7afb51206cc5dc441581ce99de",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "130691478254118429513820513324117918541731915123264797821924562170111355854",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7cd70c000dba3e7f47cb072b49987d470632ac04e229cee648d9c368914c17b5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b95665c427e9a7d1d236cbbee58da2727af45a2edfc7364ed84d9aba3362d3f4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "862011066939652559881172151292129371717587133152148134402451564157941882162186",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cb116664e496eeff428fdb5763f0c86c8c5a1f821f2d972bfeb652b32ec7adbf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2275319651124115211862188711702720012124513212446182127194170115255150155661692034340",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "855087fc426fabba5c0243f475c87457412897284c9915572194bbb619732ddd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0ee97fae4cbde04684601d97f094a89963f5919d210449c8214bc63875c3fb52",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4beaf4e20175e4e493a9136728ff67bf6fa013e37563b57a4552b72266f00819",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d73577c641d61329344c4f30d7e47955b7470b97229660d8bf3983495d666ece",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0d8759916c2e44568c5d17cca85b4df73e3b77d4ce2d56af74ec80901f66d2d3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "62115cf24432ff37359a801597b7905433a6694626aad54481d1c22bd4cacbf5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cd950ba96289812144a3a239a64a73d998768f0dca32a0070cc7e2c1dc8df35d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18512318017594122108141118509560157244204467142184511422870239124211821061359948",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1d8c57c522fd2bc60a54c4b21e85dbd6614dcc8d612b586570dd6bf81d7eb939",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7aa61730a7d5a8a233503fa694e1a199f5504f3180b8c0bca1f450e6b6a730ac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21185216941992216417150303820223465139831881332278220518015513620420025021299162246101",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0e7ff9c536cfa5770ba48ab04b0ec6f45ad80ed878e2d39f935c68e24e8d36e6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2262431982402167722017182190865921063101542184521058154108106513554121192316474",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "30586117308735645016054197911450301171410219131332412491332222281579885130222",
        "optimizeResults" : {
          "modernFormatSavings" : 115192,
          "inFormatSavings" : 48283
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/lookup_soft_elegance_1.png"
      },
      {
        "hash" : "83deb321d2a0c8bc8ffb67a7b890f022526e2352cb19c45eb91c134ff82fed30",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23812182424467421412494925224252001164880037519421521411401461051572042285920",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5517514590252742402062043918111313235915521423419416352081147112845139157235105206",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fe65948ffcbe8d5c8d8ba0c32d9be5eda945f42f10654dc630d2a30cb537bfdc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8494cea3c490b25eca0423423290f8e4c62d123543876f8f730e61a05b0a42da",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "87278ee5a12b95babf3aaa8b90e07236ebfbfaa95d8204f352b0ba92b7fee206",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "78542475619014386197116401891192343423922715281008428714319766341071102112425042",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18822120114720527133191791641731111662117978133924718621517720319222116817572151251243",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6510724541811641501731821912752962261992265218084249244171161111192399206230813477",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12621432331233316332792302151642172173232201240824344352551107319525402613512233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ff84fd1dfc3fd7e4c3d6d05ef3fa7e3e3076f06ae5267bedc1fde4f036d9ee98",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "72f567a600d3f3ee5228b0d7fc88134f7bc7fe7f1cdb61a1e462d15345972bf1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a878a0b0d64d86c35d8a3416b061d98489b12a7a9991c65eba94f7a81c493beb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4f082f1033c0db8f8c900d4f11365f584be7b9c38dfe4bbba2a146748a26b87f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ceac16a61831c61829e4a58c77cf1247040683bf2900ec2110ea502e24c149c5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "669d32c77810326029168d9456fe358cacbeac92cf03ca54c9dbf8b318caf3cf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0bdbbb99549b87ec8b8b0d6fb8c6095833c9f9420a9919217f387acb81701e7e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "187384243131351622371128971371441056714097182250472710310018520518485589182211113",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cd56b2ad2b85a89e8c91c4da4fa5cd43f3e39f29a6052c53471775cfcdf7817c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "62dabe2a6b557cdfc43f6e6f1e1c241391c8506f8aea8419207c824895acc27f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b2784e7785fecc12ad446db54aaca663f275a172e271db67c8f6bcde03e90691",
        "optimizeResults" : {
          "modernFormatSavings" : 55913,
          "inFormatSavings" : 66442
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/manage-plan-plus@3x.png"
      },
      {
        "hash" : "037318bb3b83b10064ed076be1c0e19f7f30a15c30da7244fa21ed020089c133",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "55a8f89cfb90af26e20983a5c48eecf27bf1b237e10514b3f173546e4cae2e51",
        "optimizeResults" : {
          "inFormatSavings" : 13855
        }
      },
      {
        "hash" : "b9240db57f9e99182f65a07bb46b691a9119e0d26ccdc0107b45e1d4c07b2228",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4d8f418c6011e0c35a9c9db9d34c15185fdaba5efe12b67f73eee0fab2aec597",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "90dfd787f94304328f346d6359e7dd1c8b2ffac39033ff46557f6cd5f803deca",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "608fe36f5c44177d893b5f9894045bedddc5698e8372408171616d2d54211ebe",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "239133136226160246911513277138086572099617615725415023919216723510622201951231438245",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ab3718725a148d217a6959c1e915912caf362542c8ea439c99a3de18323f153f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15423422724318557188172187138251035206239392382541884017049202146245252482035716310527",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "179337fe77a89b1ece5eef1c568dcc9f355846c3fc1f144452e948887d5af581",
        "optimizeResults" : {
          "modernFormatSavings" : 26352,
          "inFormatSavings" : 34007
        }
      },
      {
        "hash" : "2201961766722161213224316124208582002511412352451982315822120878514810281189244165201",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3ab64c6f3a4fa5792c933134b6bfc74e8fa844ad3ca4a67b90696672ee158ee6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1a3dace5fe6ef22a53a73e39c402505f93689d23393b2d6c8b03dcccef461964",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7113020823231713043581741718157252125118576240155134228516432735319214113244",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5567115202091442209144741665722910013914123218324542199411742252031831672432796",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ab9cbe01d053bab2ea5339b0f070def1083192bfd187f4253360ecafbecc4226",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "37667917210711764201597119317597402465154105181273114524820422242214488221205",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7006664fbf630aa342520ee0d89f172c7518b638acff9d034a6ed7499ad273fd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "132468512315025320761581831152252477117221017123231213168169561072331237211247",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "36482134747cf7e437338c04f11c0d890c45171ffeef2be727d159ab9fb969dc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "982452599128112225203541771502116168128902335511240142271067801057920513723761",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1641718423919747818742153142110749136227204190605124713411617181581281562822312227",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2526015241133185239212215132401722191932106177134351641582342524764102128345115368",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "49b4e8f354a0923522720aa31657986383b100c308f039269a3beb5669c4c03b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0ed123104789c99878e2957e94dc41c1568be1eeaad999391ae3b87f284448ad",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "75fad9be2afac63ef9b920224ea459f6ebfe8014480d8c681e691c72a2c97274",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0ac51d9b6a218fadf8ba7d131ac8453d82873a229d4e778cd7265d03bbc51b23",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4ae468229127194d7fdc5794420377eccb10442ee9a621d0b84d72d990f1d561",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c995a5814cabc869e71ac8a7dd34d13d531f545f6bd26bb0e7f4f2a6172199f5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "60f9f3b8f217928ab8e1fc8d1c2198e8b4205f87a4889e6dc1587b136bbf56b0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19120224790111234822171131031505834598128115685202271194160213627284164112230116",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9724519014245198135174176245139184110119181298985144613125310216917022213310030139141244",
        "optimizeResults" : {
          "modernFormatSavings" : 39246,
          "inFormatSavings" : 33345
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/logo-transparent-small@2x.png"
      },
      {
        "hash" : "4288374517451365711918121714270371217821612221380126210891452241771323270122197140",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22922096188193225861942052502142372550701906751130139196164182135198612439658515766",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2e84dc96375ec5989a0bc62aa73c037388a6c512e3c7466df85b20c075a9c9e4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2521591751681216020118531241522041302542303225310420324659251223240140118155887324195",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "889ab13bad264a5974119bbdc0d2865f32edeb0726d8e766e7afead619efefd0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "171122182412349013087521342875366618225242261236588937924620514992682472014260",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "353ce0f6e03a16fdf156d7a3dd2dd640e07e151cce8ddb4727a01dab662edfec",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "86a23cef98d619e44f74a3f0c17708c5641a69d38e050de1ea99c08b352e9b63",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19324628630187162164681108163331918813394223724846158106451114622281581822",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1512851123115391249140220185252401322522219811923925424273156140581471561662101086186",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "73179521361815310293201327712534253180104193163442451952229919041178996622310261",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e70586786677a79d456e07e32aec32b4cee74cc335960a3e89558af30be4ec87",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ace2ed834926232a37f415ed61b471e45cd1a09a414866e9332be31ab883a9de",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c02ef485249055b17f2a75b13a413104efd697998937157803b26a0c77d4e313",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "88dfeb3b8be5c3739ba15639b97fd7c36deec7d49599ba225aa3e28506779665",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5529bf725b7699d56fcd220dd55e54d5d257df0d3951baacc95f1d2fe45a464e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "93a5b70355c02602704be2da1a598392ee9a176f6dc363b2e102862ebf98623c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2381131191331622301912041123159614517211415020012212115241121112165237571237167140132",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7d8ac3954d839b99fa2cf610af257550fe09049875bfca6e54806b7ac6b9e92c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2def8c03108926697f2b9051cb6612df727e03a47cd6b3bd5011848889a0461d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2332301782122268234712305417796861181861852051661651341341801312516615412153161116105",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "84212154757619551467919810204105163216015536172602551822371711512521783520122520",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e54335205e9bfe6aa786da786a2a73c9a93029ad73dbb7670f722b6a045448a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10422760100162422191902221782431958028163182921645523788442257591233160157066180101",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f5bbb63b61429283dd1d1d890546779af8f54925b02703e07cd34908fffe2d07",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c827635b576c1f75867c25f531d1951316158d7c7575730d279f6a7887ddaaff",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "751574058590b48062c796c42eb7cd4929a7f0607f4017972127a41e94ef6d8f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ce6cc3c065ed24cae373f3af3db1985fb61aaf2ffb32fb594f134174f4f50c17",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1eac9be76f24b297b87944042cfc4308b20e612dad1737a8905b632cdea00ffb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6107fc72af509999b13cd17b4066bd3f09c51de8d141d26427bff54be057d5dd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f44a6c52ec176ff57c0532bd5a2358f4faad30d363a9a2c8aceb1ed0d051050f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "120157244248200791622716242451271559954193153602511957080147499337104190641592237",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b829f2ec5c3d7106f16b41c11205dcb4916ec537998213916add73eb216c5c8e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0cca0e0539ae447b45dbe0d0f3ff481c884993af6615b30cf5fdfbc4db489fa2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2c9e561a43217dd023c4b572e2e92cf6a516609f0a8f849f2703edc2d0a91728",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "db25d30f30a03aa06af515654859d8be8546a31cf099eae738e3bd3f5d6b16e9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8801033ce54f9e09fee70cf4dd2c6c38e194fe5d68bb96bd8732f103e81f8b12",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "196a9d1fad619eea9b64f0af767c145a843e36fbc7091046db6b5c967f8362a3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "51d7d8291037a7b7be724e1422532ef699e8c15cafdc407d390ebb62bd274d68",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bc19189bbb06b8574e155114a5bfdd78c6dd1bd09f3415e2867ca659a27846a4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f39710c08debbb2f93e8d6ad091882bab841297945919edaa549bbf49873d6e0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "473eedb3b72a09b362609fa69321c88cddb653541c0549ee8a244b65cd9b651e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ea0e52efd9331fbd610e102c6afefdc839a5ca26fd47e30f8dface58c748d201",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19619924066131166244197148316669622818120217180125888822223165448724224222083166",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8350f8cc71057c237e33b2341fcecd7cd923fb5fde4c2aa2d543eb92f26816b8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "39e550ff7122c4d5b89b4414d63a1c6df3e0a1fbae8fdcb7478d9d581fada4e5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "248167200181481773844203123841124233125105838235187168185715020322362646422594250",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9f86237884ce673980c89fdc4a2310e369e3e2044d7523ca38a4da5622e516a7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "249506581862218210167175145245131882332371417217324726108113191471148924911720196",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "33329283ecb2315237af418df7817a4979fe443e9e9030fb4f2d7ab407b3d99b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0f5311cf0428ffababe4a082d6b5d23b2186c66250486154779706dd19f68543",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16720801591161075259216214251416611014363135962313418624533916514421516712720718272",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f63cd36f605aadd20b3be2e0e34994c1e13af068ff7386d31e4916d231ce45fc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "081003f80a8de3bfb5a2cd1036a71a30e46ad2caa9aaa7d351377cb6440ced45",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c01fa800ba9385124aaff53a52f1a9bdea5fb52d0fbc0ca1c08616bc441ea0be",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c938d0e0c188d8ea4d5e293ff105f32366e60ae5d4b453f74b663d32b16d23b1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "35250213255123117862471871615471132451716255178138322351038324116614515118712448110246",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "130208166110199124387690189206241242932279219112421251732216733543472582403425255",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "213104251137125415223121624109141615021384423114917513671206417207521624511295169",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "644d5ac0653a17ff2da0b9b060cfaaa078bbeb66e7125406f6346dd26ade638d",
        "optimizeResults" : {
          "modernFormatSavings" : 38495,
          "inFormatSavings" : 54105
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/cu-turn-off@3x.png"
      },
      {
        "hash" : "2dc66317d6dd9da171baa35b6c99aaba9a9f452187c3c8f7ef1611c503d12d25",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "60038b0ffb88582145a5a8ef58bd8c05c2848feba6b26f8a852f70cf39f63078",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e107f38ede75bd96cd11895ce435af8fadc2efb85eed6b757bf1eec84cff56fa",
        "optimizeResults" : {
          "modernFormatSavings" : 10990,
          "inFormatSavings" : 26245
        }
      },
      {
        "hash" : "128114174301131381023318623118365476172619491389155228181752061831732001981163366",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "88701821722132011231801149094173126162236218202171161541841491321876122814122793778114",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18823816624920896114231538313212541201491430166521791001271561292481201052231291025176",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f1a0a6715c3fb7b19611cb863c371a6909bf59e84c510f0c3f2907de73b628f5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1421219987542171401281471151475375196163601740190895919710019262214334618133116",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "77ecc59f6f39eb8b4c12173d792c2191bb1cd440001b17a858d762b460759ae1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2ad0584f5eb772434dd2b4b7fc2183e635ba9ea2ff0a77ee3f6ad5f93bd33a7a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1761292291401101301822541182501453516620271294418010232481150901828817613916925114884",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "89e29553d062607376664a282ffb42e0e8805a0abda545a5021f969ad130bc7d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5b29e5960e1d96d9b6cf23a4cfd9e94c121f6e625b8886c05cb1f47eb7be57aa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9708ba6502ac33cb80e90e639fa684c77211bfe8f33d81931169e81ecd53a49a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "727ace3ebc9451ef87a035dfde06651b9286cca02679f4fe86801e599a35d75c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "118175741117880158772912910752115921337478968446172104200230118149401861179512271",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23573533715122311319314715121019018718317225587192177271706412173193185146155211015229",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb8c4dd473f1eba5fe115bd30d7cea59f973caceae733cde4a6d883c5d490ce9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6e37578d93f75552b326d07f0f1bed0545b5afa71ac2baf137e7d4608cb7bb8f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "aaef9e5e1ed4c9183ec288907d9a22289a2cbeb648b14e98225a0f866e593f70",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "41201178232136931731601324025286214941371461521767345141291072459410515011032473174",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "206154224177351291672495624521171392421681721261321122474841971392181721261717610917344",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bca485f51512064514a06141790b67ba78b2717ba88173e7100537008ae2e8fa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "78cfdc6028168ded8d1e6e6b67a32741f195e6a41574557b0077d716a049376c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ccb27b35f31c37e5ac4226faa0322fd9c898012f103193e7a4f75ace1dbafd42",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17511849171252124214431144320913312460119225204136222854222411161622535531146023999",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "195973361418124511571807917615415722371729336538341207112315818816620414620118",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "93208253821271412292481163314777175204221193143199228251241711297221014216577137226181",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2b09bb085a80a0fe8d82a58dd1842d4457857e1b547e0df473f861923a639a8b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2c6e812b4255b18a3f236b5fe8a773fda7140c59be3a014c8c58e0596d9170e6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53134113146121192225144219516015155961701751101014122696159189199891219228165156224",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18117720218578249922228341341822324629871682281651022342154618958818114325195158202",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7403531e2472a33943384e3d33bbf2394a5672ff58e29dd001e72b0eb65c4848",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "822815bad7589b0a56f37e9dd940cc5e038276f899b4255f6ab7463d6cf4784b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e3292c178c48589154b6e9fda2152c8a2eb9436e83508b2687975f86b9b2e19",
        "optimizeResults" : {
          "modernFormatSavings" : 28475,
          "inFormatSavings" : 32147
        }
      },
      {
        "hash" : "3dcbfdb5342c67990acc2aad75debf4300ce13a7531eca40f453f1e827231f92",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4df58ebadedc93da04503289042afe72e59ae56844d1bb58ea8d9c532ec539a7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21416620811521491898919916849341946219431491620916720119417837161916314316945184170",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "702b66b26b2b96035c81ac22e8f615fc533abfc1d1652a2fb3123fd1f39848f7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c300d85b7958273253c2992d72930eed67fd2390c1427a7e54159b671c3dba9c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a16ae83435fbf237a65b6f04dc66f7414b8f7fbd68736cdce99dff0cd8e0225c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c7bead3171085010545a280cf66264cf0f1ce6e2f3937a601e4b39fd2a652798",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2481311652333381315217885523052157220220177401217556217413118842101871621834467",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5219115745251179237127177119195411192036369361721210816847781011210817799971296010",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "279d2d4376739e6cf3f64fde6a839d332185f9f6ccebf22a32a4e52f78b3fbb2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "126238151171442918946712122171762452072318422728516117118324813019413792271220819435",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9117665921161951141587027123592032371711953652246119923112963167941121511824324923",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "188694511197821610912513819824248223170131229185452274737815315622717589170961138",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "973225118413722563233212932331038214501299430621302467511421968216238599412671",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "109159173212199851302231458115678181821212221121139131898420821451136211190669134223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "63ce4de546a6c3183840080d99f9667aca39b7415d4989112d51e8e5eb858480",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "70412131271651361951033625316094797565239111371810318621016519554208130153416439",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "26e174ab64e4e2c6363fbabe3607bf279a706dc2c764321d2ffa26ce6b622bbb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f1d7258d9ba2d64f9c46bbecc8dd0785596ce23c316cd019f66c334ca2039012",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24720124371102461501272420919819112720141294190129207250712389208123712109431183206",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "499517915430107203208190100130165125179152186274512240501160921191261921391161232292",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "672739a5e3d70349dececd37615776fc1b9b4308f976fbf47a418ceb995144d7",
        "optimizeResults" : {
          "modernFormatSavings" : 11161,
          "inFormatSavings" : 22073
        }
      },
      {
        "hash" : "100211250120771337949229250208153134341337191981684156131758612482941072179610499",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "48a420cbe9d7c5057f14378e2ffe7488f88128eb5ef173d9ba578ba5fa7047ac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a4f24e42e423915729a95dbd48b9bf602cf22e3a499727701078aa8c6c361310",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "847a15a9c7dc1db14061c7acb0f1e642a3bc9e156c4e68c338948b3dcd8bab1c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8bddc415cd8796514f2c8a43591ffc8be35c759725880a0d85a08a2fb293c3af",
        "optimizeResults" : {
          "modernFormatSavings" : 119340,
          "inFormatSavings" : 111680
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/cupcake_generic@3x.png"
      },
      {
        "hash" : "e84b6fd10f6af8b17bf8602ea3d587b7df99da9ee013c6a674f615d649093763",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb3732436854d71872b73dc3c204684e07794e6c4edb671d68adb57ca1d0f2db",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "95185fabbdb26467ddc37feefcdb9e716f0b7afe839305fd73f8ecbab037e5a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb42e98f11132e081e5cce19be7a69ebacf2f2b72ab368692b9ecf2d4bc2a1c1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8993cc573998546f7b6fe0c39deea1b0f77c647b93c2f431e86e898489337cdb",
        "optimizeResults" : {
          "modernFormatSavings" : 16681,
          "inFormatSavings" : 32127
        }
      },
      {
        "hash" : "d6bf5dcf785534aa0c4846929b02cbbfe850613f110d7acb878b29305bb995e9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "559042cb93ef0b7c503cbcab7734efe6be9158b9a64e714555f7ea0b7cf78724",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1507515498162341711291712361288423113751051422412071232491467724520445249762174101",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15311645235271572371031710368120124251243109419165711862214923410415614825121195143241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5922014036241196912477523912782239821281496729147481951532164220151802362520487212",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fc1f7b5896a8ed34a86c4c1673a8efac2f0d7cbeedd1fc5841680d41acc2ad9f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2522111642082412401812092351814422735104206201642361253201291221073314812630965062147",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "161111151911815075801431242383716824924659132206671232072220911316470601769644109240",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "db0e8355ec71f11cd9abea603987847f065cfb8e71cd0dd4a4a9909c1b3bceea",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1798712070240202321221672101941361891694723972439581717046235245176160201219255242229",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "181892534838156184626119417822714761144981907521121050241403234239111121190162",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16713180200110832489421127822297417981641122121417810167183167178922242501527324167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12464297123207127581119254281739230401122376138371502135432115781758620415046",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9d8547bf079e3ebc10c771d847d8fd2102651a44ffad11e4fbbddf7931c88775",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1d1103c5fd256af680b30963f34467544f53ce898b5aac59764bb7a172ca0840",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "34741e73cfd76781026f3807e90c3a414a52d1fbee48b6649ea61a34001a2e75",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "82e6d4bdbee3e11eb7d661aff1f8a6232df7ab7f38bd300e0c4aafd13c688629",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "432fde2ab4b146c4e320461f5be42f5c2e40b9f0d2b83ce2acb144929f8f6b8b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2297947123252141721441212263517179952046321720244961812241052551851831391301993424068",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "25282128144232173106102207951962161801744292225200113235123782231253183361179737204206",
        "optimizeResults" : {
          "modernFormatSavings" : 188913,
          "inFormatSavings" : 119726
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/lookup_miss_etikate.png"
      },
      {
        "hash" : "0126722312416210921457169146220141522491921782482331214097812071851862452112722923239",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4b70a8548f95b0fb04f15a34ba4b99dcdac9350573f47813302b815aca9dae37",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "110135259222575673268253157113189239203112924718613251178131125812510611743127111114",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1e90d055730b5807ec3e34366e460e9cc830e27aac2dad4932ee404f45154acf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bcfe2afd8c0a8f706ee13beb16c23d9b3183737a4b877096ffee7bc70ad7446a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "77c2bf2710321352e311830fb31427b78d4a5be5fecd0d79bc0f66942dabf0dc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23562532418110818248135390168109572272441616119512210175221522041721161939274471",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fc6d899ce18002f9abd72d26165f6cd24031775aca8247a544d43de903316734",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d1264b7f2e53510c51d8e5425db65b8d89865562563231b86cbec00e4e82b62e",
        "optimizeResults" : {
          "modernFormatSavings" : 10542,
          "inFormatSavings" : 34980
        }
      },
      {
        "hash" : "89c056c8ac9a4fcb43695d6166c4eb2ee18fe4065065875c45f56e7b4df036c6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "741568511798901341389716170451132445416210151139176521542373620222898184863696",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bf6a11049cf275cdc93e175b0f8c9558e89bd46ea0003b6e7aac0fcd9b3c15b7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "88120612390764834149239320111220223519422323524514315915120183547161150753323097",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "06178ca3cf825490dee50131a5c53e3b0925b14e6d628296663f439bf7ff0241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "219193210167441622091212011221385471841901522112181243779117119122010219931239112188232",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1631214218239942719234631311011145213815822817010816662154197133224111917419975104103",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dd7ec3a39da1a5a327916bd38b901fba78a7fe9428cbdc28029967bb29f60b96",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24fd6320013a110da898b0b73b06e2ed99d9153a41312261d4e01c7d39de36dc",
        "optimizeResults" : {
          "modernFormatSavings" : 65908,
          "inFormatSavings" : 66805
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/resubscription@3x.png"
      },
      {
        "hash" : "20203222206019312969145467510020889198130230147123194198155181042428824014899179241151",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0e138f75d63ddb463a84bc2916d5f060801fe02110bc22eba66b32353682c048",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8fa891404b525e3a53140f384d5f5aceb54960c833dc7c7bb4c2b82681df0844",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "35e1552e1ffa36ed52ddec2cea7d6c646e9f91a411559d95a87b09ecc82a2dad",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1722021491631371191269244192341219975107104785512451281513516819518212360221509434",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22525484317618114823313611010912317355231101429137196252532342204922113221612876104",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d804c1099443c7dcacaa5aad14d9939798d6ca2af3964ce1fca25e7a9ac103ae",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "277415519535186351391921432071092320466179124206240611911852081835691682207310615922",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4994ced5889fb0d584423d65e1cfc03e115861bbbbc7e12b13ce8563bd00529f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "adce90e37f0d6789fbbe54b4a17d89c145cd664d4150d7b16fed7e2d8c49fab8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2633b74cdbab774ea0c94e5bf19b60de2dfb224b19c11a80b9889c35a315bd46",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1254436102321001009814421013622122011218542531184443215819012971226223813821520677",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f6aa9cf6979b8e426f7feeb6ab4b501628871e92b4a4a653e8f2eb5e8a99323c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6812616366250121137961331262112424868917186558720221331253146551431010011519482",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7124464234965232122012021161123651139100102237249205318214010448451822541883226187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "176631515359203208159283926553202312118522922622218146104189271231182451872315123",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7157254011713016746421901346531227211341961092391931751442031012952193183189172167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a2f0f468783fbed2bc84b2768a5909cb190c50e28b87c2fe799e32c56e3ff349",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3960cd828e5bcd80b22519b7b62bea2e54d3eb0b371e3a8ec2b82751b0baf683",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "120272350104126177227122227832062451377246342552873161391231894845248134148143184",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15812625273126323811219911622921116886192139772511391412558010344121811951851101041182",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e4b667c884568be13bd5bb8576736f6e72f45e3a6287a8d6c30fea443544812b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "397f59b4b283f0726a5c79b8e3102d57a8d27368774b39e64e71f9b541955e03",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15123196657963202292399118217519214516914813632721096581011802091749316011918778",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "870b91b079fc44297faa728d0f13480f69bdbbe93fcee2d91b4548c65df4795d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a6c3258994af728a1bc48b089931c87c474a5ea44a9754b67a873aaa210796c7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b2492a91395ff1929fdee06247127563a1f9ad30a2302b22fe9d8834a8b60e87",
        "optimizeResults" : {
          "modernFormatSavings" : 17742,
          "inFormatSavings" : 39427
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/congrats_work@3x.png"
      },
      {
        "hash" : "40392262194374130189416420153831451938817914229251162491111872272412333819410998106",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1021287211891792520823922915158121112012420569231211351131724030160699924120058177",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f7b30446b9b19df161ba111ac1884d8a7413d7d70a2ab6fd9b42283cb634792e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "252227122769016620874204245239792191421471641602091551412342251706449761191242281135472",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "234226143117231112189341043670225418816217235621283622524418418838711411541172400",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e3a3cb7879f59362bd7515c249152f0c6fa07106e63f014b53d30584632f2800",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "967533be859c93308617d63145305268250447a3c329af0776ed4282581a8941",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0a7402f76cd1bbb6bec3254b9471564e4a34181e15f95c08d255caf4963ebd1d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ee31a4dbb54db3228e968b0adda0799ebdd1f82949bb42d5ca0a1e4f5c030056",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22873972311622210214111122814116102065125019423243391981462471921972281418331698119",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19583119170236237121851372719992115318269803089162144244203165532012026922811120856",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e7837d4942c1f9b09f717e0c03227c4c55c13db9938e7d103169596c4e3395a0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "013552152542241083523820922169255741401001093946235184228247236621861281512387422828",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e3563d0b8149be3c41d3afc6ad59ab90a93348e34beff4a096b2bf961212107",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15074616ab0652534252e164aca0b3c1300957f18d7f7e1ac9d2dea3e4eab4d2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cd1c3e4b19155fe105c08d8a29b21e8641ce2f7113bf0c3da731c23fb580ecec",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53182238174612413524317426175209177226326322624522819614119617913915821910118512225249116",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bc325ce08801bebdf29b48009bcffcae3752bc0556cbed9ba5016946f579ed27",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "aadd4df77af4f10f82a4f5b32a1768bfe13f972deef90d61fc1118834ded8cfc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19527338914910819732247103121125112211231501318812429251271896324974591031320266185",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20624123720318012322512423884721182053111720147220958017696150368612370248481051728",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5a64ecd597bb1089b83d1e3326da849a5b2afe8deb4390bcc350e9f04cf285d4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20383dc38b134b158497d372597b352a8acad3758ed05613c82e56312ca9fccb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d36e91650ff93fcfedbd1eee7f0745a1056d2b97126c49572c271362b6d11ed2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5da71935bc2fac265de30da1d6022289d2e53145a1ee44fcb2901875a34947c5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21419217870222140149150255217190431221525418021951236581981201882308679728198108141",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3446a939b4b3a1f6a81dabd4f8e0f84e264e110aac2c7097e1c7f04f13f815a4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0f018a223209c1d129679e020c62a60dd8241558092309ad8145d4b0e13eddbd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "153052951745413299251921407396411806823633246138217154170218186228911312481421617",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "609978faad4cb1c86993765158cbe421bd8ff30ccbe78d964703b76b42f67680",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18713928155162109992511706084023716581122971600151163218142452256103349511553170",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c779581648b31ee744c3f1b97961f4f776d30308af9683ee39413a3815caae74",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "125783711245818317620170199822266420616149621842402225019145724322911461201182113",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1412102612825210820010719713424813925421123241203102127225959511412413516013438011159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ea7ad0913f4274bedbedf1ad84c96eaeb414fc975addbbe821623aabc9d8f615",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "716b6a13ceb3722136a1ec80ea2af6da40b3d266cb3c0c47233c843be48776e7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c7fb5cd7e0a3fe85dc0d2d03e47efea1457a9c886ed1aa50da0ccea7d6121b3a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1612061291472142161498523157177705234338019421818514920921220901491874215510584149",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1009062175714925536206121612122128230207198198137220108292025969742501101786013652",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2b86c4942933e0d3473db695eb7dfa4d6802383aa5f33f23381ff64e23e02e35",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c53cc05bc8b3ca1e9a26e98bf075b80ca45b5d41be71ef8218815654971cf32a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c4ae06e683e1e28727f6162c9136230831727aff5635de603cf72637664bf61a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d4b71df7c21196a5809f490c2fd5695c83c7d4ffbb7d6314afc2189fa613517f",
        "optimizeResults" : {
          "modernFormatSavings" : 48699,
          "inFormatSavings" : 52403
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/direct-link-permissions@3x.png"
      },
      {
        "hash" : "2381592492541613325862461351989816316923618313672271851875187219170252682332777156204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d451d9788cd87e61dc51d39d1de441c85e88c2f455d99278de58112479e1a7d4",
        "optimizeResults" : {
          "modernFormatSavings" : 19427,
          "inFormatSavings" : 59463
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/vaultdowngrade@3x.png"
      },
      {
        "hash" : "7ca14cee95db47bf272a01605af77a33498a0005eae3aaa0f93a9e2ef9f5d39a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "26169145148362131442421295249418323915292135718717646223601341181661381754114119",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6762ab59ddb640c863a1ecbbc26dbe19f9ebf26b79a6e0694e973f73579eb30e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1751323210480197178134431961262461214266114212249127186103161111198146010967204110151246",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7ea26971dea4d1c447f45a8e93e4b028087a3a2830c6fbbf3f4b040c1508986b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "981991042132368719817522711369137222350123971091701373625463219169167661291059420543",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dbb81e1f81196205d0a44a80810f914143f877dca92f7ff5372b9fc1a16df7ac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d4299aac9cf767387c3a42f7f46b1efc92eded76e9d67d691f675ae08aeed5aa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b6041f4e9c292d381d6b3b9f17d682bbacf80999c163841c461d6095ec4aa22b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3c4e1f87eff57941b431a13a823d58376d7f40ba89d80d338a74febd36deed27",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bd3607ea79f19822577ede4a882ceff96bec62e6e4e7eb508a8bbad04e2fe029",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e9e660ed6fe70dfcd039e44914501fbc07f1d2fc740d4475205cc257f3ad980b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5a2558cd7ffd3256083b5c8999b69463bb098105f0e4f9b60e0cac5f0545af9c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d100b14294b5df75c0ff02e9be0612b2b09b177745bb412de561aeddfb7799c4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53206181571826162148795873134147156424321797100371548594882221792125320313205174",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7666f2439a9fc1ca4aafbf12359ffa43b22b244a57982d4779ef19d64e8668eb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53106251886612712235914512482271321131566952850159127250216652351318071184130133",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dec81633f73051dd80a59bae28e33c90489c0b8cdd051e15beb765e98f22476c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "47112201511125225570501161338510671732261232111285817911317018124451553510617495232",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ae1f47e7714844dae6cf1ebc1793bc81ce9766b983a857340c16b24df7866e5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3c1d2221b32b2726e04bdd871fe136cb76e94c628a09eb659efa142638a99853",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "954008fcc78f612b9f5b52b88c733d7c0e5636412da602e2fba9246f73a27631",
        "optimizeResults" : {
          "modernFormatSavings" : 5065,
          "inFormatSavings" : 30404
        }
      },
      {
        "hash" : "c2c9c965c2c31b8571bd8f75f93bd47f36db4b27e0f5e7d0860e38fb5cf23ecc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5b0c16522c0c12c1024ff520ce3023cfed20fd424bc786b0aacdfa48a621d1a0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ec1ff3926cbae0a7534e23cf8e1686c70a041ba360feb3ea7b4c47c3d1fa0bb2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e37d838556643d986c43a805316f4008a636c630f3250dde1c4c4b861250d168",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9292bea39850704f4b686cb45e46bd26d7003b858952e46170f96e404b43de22",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19415311721410622213732192432421449177177215182253175236607518086214252412281395241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1f73dac18fcf85a52bfc6223b803103e78ab80e4f374e97db6d57504dbdeb1ac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21125179972551491991485734721732195710911111972203722352421661318818945253143249195",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bb8dace0082bd9fc0b3fb85a916f43ff348304e1fd1059e9eb4ad64c28914207",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "df5e4ffda2d0e9b7778482f776676ce816b6fc9afba03bda416e6bc447e66cd7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9ce06ce023c6643e30418f42e67029e8d5a8395a62f70dca9f9f5013b7a944bd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7618212750721017520122112105182331372281648158764853212246172108561524944224715",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a8b405868e745a7c54c6294b17de575a6ce538614bdbefe212370ad1e01f048d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3b540391b13464bfbdf6736471118a99dfbde9d087d83738488158b1a246a9ce",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "380b2fb49089758250726925d390459f57680eb3cc8924df6b244a690a4d0f39",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1051217419009223717142251186581462422122191679760216172240221156190641282392915978",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "128180701041552171791261162191346512119711716010921515016566227663622281417019516017188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "212201791119078311261011993435151661361262230154182126441661332388567253111829169",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16620695240224774215425160103424417216220473822304712578155122551563912521812720148",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "33bca045bc541e2509d770225fcf408ff1ab4555ccd50d632452262f740ac010",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c6032d479ff139084787576389080e3ba5e61e3ae5d7a2eca7b2d5e89eaf7878",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dbe0b0992c5f0c87f9415979f708c6d985c56c06d4be269d5e46a2a9b511a69a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "487115310725520242159271038891571602531496313060441913535320429131533519222441",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "122086274190138819010458615724688810512320611127169215117102522458118214216834",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cfef1cb23c56f5a1007ab9c0075fa6b47773a785b5a0d6d4ee3a995e22960944",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "11b881368359e6eeb3d7c4a856dc50872d4231177dbee44c8d673425c2d7e847",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1757a972c0737280e190620e6df64b36b18de3deae064f944abc4eb2ffb038a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "251183152198171138196145472381115512112415912710820845216816924311020812624115121893",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "178111155192197116531074723112911715757153119227891691814114148153261348316019415017790",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6d41abdcd4c60db601086ed49e696fcee535312bd341eb358b8bbe698b339abf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "52a9f81c91dbadc5c20d7d7e518d0ed947188418419d5051da7fcdbdaeeca9be",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1822212359190109198169168165220515418122813527104171203131241165771035795214161835223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4cb98311e9af04dccb03f378f886695237583dc43b140827e678798f5c47f2d9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "289102b0d0cf8672b449159f425ce74248c5a4dd37f8c9d7f1a729cc8d9f3457",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2011262542071426110682221356128017810048222042171472442204416918016616069111215128",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b9727b1656abcc6b7959a6cff1c040f31e4d9cc4c07b635032d4314274617dc7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0212431ee6718249e63e3a2f726e6d0f9191f2a044806bb8e6c3f2d7912d711e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "851882441691821802271858710022185265291610318110555157161186217572277672961014846",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "162e88634115b82cdf8a02249da043b372281cace9ed06afe39feb7e51b3b578",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b9221b46449919ace128edeb13819efa119790daa36754c5a6f0b5311c91d475",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "da276373781101affe07a9a66d453babc5545bcef14457f35e48d83c9a124fcb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a69f7c253b0c398f24ee0ae3160507940558e04d481b2f5b3c4ed1049b885d7e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "199251671262032212051313492241186113115201229220402327819023614119179944812651124156219",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8a085f52a3f8d2a8615378b4ab1329b456b6c8057c74d75437258cf5490c6137",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "70631961712311233211165486921180230186235251254244851261881952181531372381641225214196",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15917721219772132125255194478723912293247133156153117144942471721331302171331767323153136",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "100321401742242375877272944216851704624713115325012712364176012810715693120244108215",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2402441184373229117291781359118412524952211104618324523344174137271912423182165222",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3542eb560044470993710b075551dfe03e25e84670ea375b9a6c5003a83b61c2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "177207100180249231328962549323716782549238251562241181142481281518255315554141214",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ddaa79a85e9dbcee1a36451be30bdcc471744fa1e557099f74d85ca5c7dbe23a",
        "optimizeResults" : {
          "modernFormatSavings" : 26903,
          "inFormatSavings" : 34118
        }
      },
      {
        "hash" : "13312721422219823949245147181389181719411396222381102042144215510020210026181241195",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a164f65382e3eff713427c449ab2fefdeea613b9ecb083c533ae6bbe6a33596f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2511096392342201611681576925117615817825416621260741861171991510974081921812153159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4a5e5de8abe55531cc0e3d5de22acb26e45c544d9045f541fae041c2fdef12b1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10328134227228251146065113136201752282512930175149245215241181556138186126196222125213",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1570c08e0e293d65dd0fb3aa452dad5ffb15ec5d364b62350a1432522e38edeb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "190227107883689120181711232613121620931002281561862264927149250171382455272203885",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1207610013820767155171182159169151512811515615417518694176135424921623060212238293208",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "381918392220555148202046912720111622815178163388120983111602090167213220145127",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fab6d64b294e4cbaa8c19055c4b6379663de49e56dcf7a240f3902432cb0af84",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "78b2ac3deaddd088f5e5bb5b4a42a7274e01f91bc774f918bb7fbf22997f2319",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6d777d4730debf31e98e1f3bbcdd762f0b898881d03323d93950752aa21caa44",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2ececbfb5af44fe307f2c77dc60029667728eae4f0260a163a5bd6066fab9a51",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "148247103194112235211364140010225120318225523523210144232382371911161887514610865120187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "448147039155198521151761031721029612770199179106291641572046310421420811262119193",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "783b411edb8dcba32fddd3242c447c62e5f0120fe290b818decabce1752efd28",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3210647254116791885217245186219702441276216314613842201168952391601282371847115417023",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "63ae02168f2bd85b2ea0ab5b4b36718054a88348de8efa93e967e23624e4640a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3ade3047eedba1d112547d99ac68a2186627d5d18dc77d734060bd18ea93c646",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17821730185965043205154732012472431061491911151481651101548255337225235230941194210",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2635da17141934e7b05fc644dbb157e57c3d6918fda4141f5cabcae0daab229e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "56152142141151982171574395142179581291251511442511318022191109262342008212110796107240",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4361537e5bfd2082d0da925e56e3893439d8a6f7a3c7825439b13b14db417e57",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "476e2c0a58595d3582461fb059b43e634e88928d4da2f2f298041b8c1d6db192",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10720416621165824510533249165101252262171141691743541711199824810121922713721016419190",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6014572512089723710613678139853218010017416011317513524013695229185539724186224248",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "741741544617070472220183771183624013871238101212217107225236128193261834219509090",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "07251ebddba372b1156b27b6e9517cf4a67a3d1686f3ec7b74429cb6197cc132",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "741615014206101241305713423824676362958219171110846715613817848134200931834442252",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1788916321057174162126212240127233316281291761832121341224810286881802347613116959142",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ea8384203e03ae3833c341c5e09e5a1f76eb6499017572b2096be2ee7e2e5eb4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24862519721412549208316585261061318914944185187150101192401116130205112323223072",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ef3d91426b3fe7d752d07a926937d00abce9219d571b82d10b3ca473ce94aa02",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "252201311101204913319817816018018513297462521831561991241588420216520216913881799528",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a9700142d64b9421212602e8d4b42616bf0a3456d690654aa752a5fdbdc2d6f8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0c99685acebcbf43909db94d114c598c65fe5fe174506c6ab3ec9d5eed1225e8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9042a9fe596a10dccec98a3fcd1fc779be621561bbb30ee23e358ba71eba9eca",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "68223129257521063750191751110524926918479312236514544139912386620769171145211",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "babd2329b619e31767974a3b0b248c642d2eb9eb1feda1e52ecaad1c2ed637b1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "199224571522719210845222216100198342511731702322251372031005928961114422420471113",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fc02ebd993fda8f42750c492371f70c09c76636549ab8541e21acbbc9d34ca01",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d8f8a9237e5e3abc33f28a15a93a7d92cd1befb48e4e8c8a75edd717f5965bc9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15863200169131624125252620151051492062572442271232461228328212163620421611393130",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b55c725b6315e6df0c1f5629a5f48a7bfb40e627f3fb94fc60dd23148e454b04",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3c616ac20085bc114a74f93f0fe870e0c29d0e9ea2c119b76f502cf950b1be6c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f4c093e7799dfed2cd899e887cbca032ef9f375c18254fe1dc91ddbb03f3ed09",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c5cff733c9396a359e26b7640599ae83ad77564e0088a6fc502aa46ae52b141c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "100169236150106157223136121472141255932382143208462316017614719016120810119982211594",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a3db6e83c3669385c9518cd26a4f9948dedb8d4706838f6d63292008ed476e4f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "26159133213131104126147492418513528151130155616417691622091634051822036125225224103",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2001756922891031146651521942191401747612415619522241122165250193965421168441347749",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2071834831190247019715415224935180741304116336141171127234342204941211129219121",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "244130363174147117851271531432252484825211224598831871292077489149136141821481215597",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17226166199195211128178341411061771973121081737120615322713931522432295863025143188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "598864e250ab6e6accf9a88d9297b0aa27ee6bec13c4ac6c7077bd5b0754285e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "438324127228163511754012324724827129105214246120152254117202972072352321692617520185",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ead3cbd5317dd9251b9f14b8ce956658ab1d5e6f57e9ad36922e55a8d90e64e8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6d4ca242750e33764eb03fff55c6bbef9063fa3d12326f7ba65ce5060e45969d",
        "optimizeResults" : {
          "modernFormatSavings" : 28246,
          "inFormatSavings" : 41117
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/blank-file@3x.png"
      },
      {
        "hash" : "105447359189131204121416125219118452357617714222414617116121914424682203885820262251",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d0d8fa4e552527dba9cad7bd6a54941270dd93f1aa6a4691c902a787b0400248",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dd3fc3824fccd22f1caba517e5d5e36c9478f6038b7d6adf46409ae6e93900cc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2542162422412925512519602121336583190163180131133247998456213117225162258525120950",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7cd1770a487dfdbe1c448853db1d88e154ff47878db45fb99a8af80387281687",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0df9f0ebc78c6242acca44960bb2d017e2926e1b06f5a127c0ceea719cfccd36",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "556ef8db6a4e27b12a36778c2cd8931a996f132c37aac064dc517436cf57d9a7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d8a26cfef659ca38942e7426a94bfdb0b89d7cf8b1d4155d97dbd0b7c5832cdd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16014257491607515207212781499172149228239223624220832214518413321720711731431",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1981651218411222018726191156194209819221118311111913223213145235457162632327013460",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1352321681001222801295977222125177132175178155132821369215656152959365222721523",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1142381301144415624647185619597235877117616210422620510123510247542018116710418559",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "332176ddcc3477df0bfcae1941ec17ae54f0ab658aef7d6abdc48b004ee4e60f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b7669ccdc7ff7687f1badc98789c8f2daffd74cefc452467f9316b27a72a06f8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "371b32ca8e4099e9fb77f6f47b37f38445fba03f87e89f1aa8550121d2d86f4b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5917e2933b47e97e55b3b8631ccf16b95de0041a12cb35dffb493e777ba7fc82",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4a632e24179e5c69ee32059c539e55314560f8de8f08eab01ba15a23fbde7efe",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2813143771961125315222511520097682131623929234253123142162341716194422482730175228",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fcdc3eb568d5ecea24622017bfa717763e55dd6bdbcaf906917225f627da707e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0eb4060f1bf7cacaea65ba3f17398edbe25e675addeafa20818552b78aa6c585",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "392111178164239621719524522938732461314394231191592112321296823313423568805923",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1045924123018713434158315084401721449821152602231321612512412361123399841622727223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1761192116244193171592058875183159169923232129179194234124147801388724337911106120",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "754616095101919016717416196247166159149205668112923249152140118237165956174187188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1920511921123018515210715516920814315915714561321716817951253302513449182185652293617",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "81fef9fae0c781bb01c8e2953d7c6ba19d913f5c30d1e0896647786da7dbc0eb",
        "optimizeResults" : {
          "modernFormatSavings" : 34504,
          "inFormatSavings" : 31792
        }
      },
      {
        "hash" : "4815315623951236224194901876415925122047178175165129541262132022491191971605829224246165",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fb6dd410c2e8319c3e93f4437cda85558bb8d6d8c4f657d02865635eab04159b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1071251881993313938134372559623871012083821565751392027890136124217121321011827130",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "48d54d0dafdb8135ee257a9ae2f99dee36539d136f481e7e9adacfb673d9ab42",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4624038190255198318718118965159190225971442161281822479015610728892391763751111173121",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "232ce8f0925d00dfe7e4e470612db172c4a97997a1342a219d940051e5501829",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6b8a3677e95bc8b4e318531feaffad69ff36a164a70a4c9f814569f1c8e1339b",
        "optimizeResults" : {
          "modernFormatSavings" : 37872,
          "inFormatSavings" : 51784
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/vault-downgrade@3x.png"
      },
      {
        "hash" : "201119107128628422288147231921017413721260158117112178229137565620121722752474777",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23432501362511031564687209113105136109250601982201992167187193726422444262172119226",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "191102197193241491282505649137502141961131922451048315218824233341361134101186318387",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d06e18b0b0c380327c908d1c54ab2c2a692b87063ee433ef03be8373c9dba8e0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c29e0475ea5d7a7ae49149b0e5e8c2327bfdcfa89f6edd2d4654177bf610782f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "239641119113711159658510130132228416817115957237194282114916567410924520888",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1261051971738959931601013518424918910215412070885512751982051821461111157240132114116",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1c63daa866c54e53dd01baee608560b0e6e270d7a9c4446f69de93c2f6628a1e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "976c67723bbfe2061d9ad899733d63eb5e07adb8f84dab55cfefcf37aee6f710",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1692302288613615194113241461371247921388211741371026171160174231126161101271092274141",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1431858323031730215172130201761442191262146591042522221911664159482527880119167165",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c0a912d7b9db0e6153dd4ef55c723354533d186985f7bcf690005fad06d49884",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4f8b5bff0fe04d42ddf61eb051893fe4b2202a087ad7c86ef3e98caf4115881f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71137762041410200244602041985191175192681428416122590138205238157190186792618283248",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21517421211998301121502261461314822322110710182240192233994802552021982204915355188241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d1da17fe98764d8992acf6c7216f572487b51a43b1ce3ef43149b217b5d5eafd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "743063f5c1752571979963977a614ec132e68f7caca8f1c63c539b850748ac41",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2480777473911711882482131081361302501958330226108135160241121910131118137603756121",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "30244122132158167204216236342171011851815110124323013278918496253871511061438111654151",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "daa8436e05d6a4063c202627ab108f2534df235fdfddd4c29ff634b284a933db",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3887c451c33abc078f17a67eb29be131ceaa044814d7b5677a83ff144c5537e1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a84469ba486e381f9c40b1e047b38e33dc2753838af74270be066ec6c527a112",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "59842041911473817913171141692615148111169199501021911721524917024101385124314517484",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23924522414086172500121122231745161613413817975711105021846379290571310385",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7ff82aedfe9ac3bedf7d165434bbb4835557ced93c35671eb2969a8e53218ee2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "977c552ff3d2eeeb5b7067b7f1fdb45733a05485b0b0a71e7ee113c6997c9ca9",
        "optimizeResults" : {
          "modernFormatSavings" : 13174,
          "inFormatSavings" : 25137
        }
      },
      {
        "hash" : "5f9a56f7cefa52ad8b23e5c41e9c590dfc3b6dc09141e7b4bb8b92c2c355d795",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1696715324710522118145701267413215926237134173232182522017010317521923561814720533111",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1032052152254612915319472216721015818771175101239197808717017710019615878177272419481",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "13723311520557395124789145014256514010621416019827050255141832222211465774173163",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3d6da005951821b6236030b8accbc3e23dcb502b6dc3b7d929b3829c02e9b8f4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1513611818675991831632198820512712253224327179170882214011760166201538943156105255",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3612401681341003919921481261912617914794190151100261692401632124451331759910341167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "241611979064145203125618215519125510314262108253291892471665978622331545618290204194",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dede910645692f8677d79eb125a3bece7870cafbce33b56f4daeb3d0fedf8c1b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "eb96ca362392eda54e37e839b80a7877c3d06fbb61df42a21243f48af196da07",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d5dcd339a99349f6be2b937e3d8d69c7c205ef1c9be6bb4f92916dc45a8455ec",
        "optimizeResults" : {
          "modernFormatSavings" : 55564,
          "inFormatSavings" : 56642
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/cu-connect-computer@3x.png"
      },
      {
        "hash" : "28820e5e4a3fbce6dd5192dd52b72cca1609f468b3bb5cbf9d0e8fdfbd93ebc5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3a4f9d45be304e4a8ae3621e3bb037e2b97f69d260c2eccff59ea849015964b9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2122521971071335911614270135115240691978924520213861442481421852162487471261856424120",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "77219294239203229372558713491431977363232432081933624341501241024111418623391",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "00c7b43dcc9c59fd0aba57aac9a62117ddba451e1716a84dfd35c6fb80ee492d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23177a668bce9d63a50b3850dfeacd113919a6153785a61a7e9d26359a84fe81",
        "optimizeResults" : {
          "modernFormatSavings" : 37542,
          "inFormatSavings" : 65721
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/illo-cat-umbrella-dark@3x.png"
      },
      {
        "hash" : "bd936dfb6db8eb726f111ae955ee84f9626c4b026e52b788623b5d3ff1f58a4e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d9fefe9877df8844e50d690385614465c02c4375191e8ffb9e8f490b8cd3900a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e336a4f1bdcdee3852e5834bf9691a1c2f710a5b78493a120de59ddee4ca45f7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "151617526101251381397392221461282481265875531021641141581348622945812722822019123",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7bc8313ea3f1d065d10b31e6c6079369006013c3f8d3668a5ea39ae5b79dfe3f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f00a3efbfc35928bc688e93ec49169ffdfe376ecfee082d6fe751ed7ab122876",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "40c95068715f54f58f9688c45f017a56e798afc3b6a84807d6a7cfd571c75508",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12083354a2e3ecedd283268afeff097c2358409fa8bd80c8b7e125546770e145",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cf88ab5b59e3a04b124e8a6dd254662b96c5cef2a407270729dee909c309dc5c",
        "optimizeResults" : {
          "modernFormatSavings" : 18364,
          "inFormatSavings" : 36906
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/device_full@3x.png"
      },
      {
        "hash" : "254122883181233314311132331892312158514732823514450701911601901182919479196121164",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "461004052472108423540162261857715020433144218311144145228239233142901775117117174",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c1f0b7f722ce0527b9ffcf0ad904d351dad1fd91a0f3a7e3c48414b309f3fe44",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c755e14f2992ead20775b8060834507843a0ecc70c4dc066083eaf6f607c8388",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "97692321822091681574765141152103655222462183223107136153279015210919316218677205171108",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "613301783234882512372064312186138871322421815165217921162261801551348521322214",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "859374dd80c7bcabdcaaf006dcee0b2c7cbd1dc57cb461049e1e5c97fe51655f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8b4ed8b78f27d11b943065df9f22d33cf55ba24a08efb563a0374e6745b0ee10",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71235134124961371647552342321642411322054550381615218615429424739145131137137233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d3575b42ac421fbdfa5eb72c82b42c84afc4ee2935d33a3cf13df5a5bff77ee5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "13621822241452311315911791925588173254661461291169621820914122224136110241494626197",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "118732072471661182401206814018615919025510512719714325563196187461751872239218652523550",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "692061604620291153623381042271742129771451011871151201422412923119124622824819215",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c208f340464f74a66810fcd69a54c481b0d1f448e7242214b311b00c24691ae7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d926458cf430609c0d9a97d86b18b18c768e4182e024602c52c0ecaccee14a1e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7121512962181291091961554382121651495152641866371162262559839523413824421828125",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "146227125223118419424173168146145140196211908712024224823188191253134169581287444116",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c67c31518802179a936619e3392e32b811be6fc44d34c2fdd233c9e27a590ea5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "531149934867844212245113428817397216247191321932498658187522711169622217104241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ddf201ab262fa5c01967ab232879f2a0b29ec9fb715353b6f914dd1e5109d56",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "65f51498374297b5f465a4d397496009f022512b62f8497bee0021404e667fab",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "01f227629fc8ac0ae3230bd4bba4e45de29c394679a55bad48e3d2637cd9c6d9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "697862050210b0047e9c1acfe34330cb000d3af388c304e4ec283888da13d87e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f43213c1126003067f9ba8e4bbbf716a2ce4eb72d218f827a381690b9b415612",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1195229122157848193214218110824921324012607913324937521572111788158482140129134",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "109725641681318218254247621963211166188258314987718610125518120855151138177161",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24420522412522413924318942438235227723420231314321892147855517352326245423",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71ad39fb46ec58289cfc65d9e46d6e7eefc5156d581d168da52d79cea5abfddd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "43823194202131994315321649249149190110125120712718125315097452234208127226525206",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1972126601512211155511822313282152112501581812491714122636171150421101118521720754113",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bac803f33d0b959c9334a045cff6557e62fbedc68f070b0bc60168c7310902b2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5011011231076222251516515180184102509640241413520880140153106742331751425037168",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "240102149106137482104120218023112222241751972278211714517320856139476618610167100254",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22013691801219616919683246210497721212314411010016193381212479522521661920185163",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4c7b5ccd3d58ff7b6750ec9695f243807f06f31090445897cd1aa63914856917",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "241798d63a98a9de6fc1dfc3478bac132491ed5420c29129a031607028a995bc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b0679895fd856a0f24477c6c7572283e877f56500a939f98701bc0c16216b0ad",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "347126164711754118517315020410914823921813523181220589512725116252189811971186100",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "97721811431328519150199243194210184121194745730229203599275183213183797250235141212",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1538618513019211992178151382913609521217619234629125255187111727113523411342255156",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "145562401231144220213627175235673116355847612910574443719117462192121126189247167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "142970a2adbbbaa968885ca19cb21cc1cfc8b44c5c5e21894f232ed80d175137",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b97e9b86fb460d6840000ada6cbc06870fe427fbb97f4a861ec6a9d9788f5b39",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7e1af83c574f5b5a662830b6b50f597ab52be59031e86026c0218826b1e16114",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "77f80e77da242abdf7e474af88fc2c8160196c07fdc04f7831333a5cefcb14be",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1301372219840101777125022521777143531861602371759817312221824653263221718212937171120",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "96996aafbc9bd112d50aa5442d914f93b0b2b2f0bf15a2d8679ec87da0a312c9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1631141891481091833013335971832221652422418116610318224517244132329816221825413674107110",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6920960316718846771951112113318110720017919107721561511142082372472418419313914375",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "39259bdeaeb3193c75a5dab6a559c51df272e86f8a6e9fa78ba316813f6ca340",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "daf039161d4c0c74213f375d39a78849b0ed034dee5d5764bd036f9095971617",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "01f08f3dc8759d644512ee924f086cb38ba08bc1c4f52f13dc75792ab4224ab8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "804f798fb6cc22d68a0964e638fda101f14ec4f4dfe0e148d017a9ba1cda865a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "449f8ae8a11fc6944cdf91e1a3c497056c0f14e721c7656f3217930c60daef57",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2124121122912335231213214183206971161325948216965616177247981468013624912616914824",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8f66a367c04ba55c8db180729d05e062013c09c3ea0aa6fb190026db667b8688",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2538457379323819739175217129124521198261120186691111322166238186202116862782",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "afde533205da1456e22e957f2aa4dec2d744e5d6492c0e70904415f84efb963b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7e02993856a980129c76357c06c78d39cb80e526e39523dcf44c7c2ff2884f74",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8195133582178818324171312531781111032427086921151781586193651191244916979137108247",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22832359922677184019555793623202401074995602381122091624113018418537126503636",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a5be48e41bd6c4ea6ee0be176a35d5eda6a4e01391a0214384915aae4a5e38b4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2332541242071137291951442012235207924712313219237129196194124812471811641481662551249",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0ed789a95875c8b3c53c4baa27ddf80b65b66413707e6e479accd39b9ac36728",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2f51655ced9bb662a597195731ad213707f08add653d66aab36230be069ab2ee",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f29489f0861160a6dcbe7cafb2b20a5aa8d228250246fd1dd122e6e304e2675f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "273d88f9486e22af14d7b792c6a0d74b98c381844d0a2f3ee27ac0342fbc3dfe",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c97238ef40031760253cc4db9852e32f813a0e3b19b195c7d34e552a74948eac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "11687240106161109443715416753127167141191819063252236109674416113415964932185224177",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c8ef5e9b61c4df5e0556f7e8fd4e7b9286b78dc292fafcb13d09a72acf019b24",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1001572203517414021013891078511212787198160992517221024489114757322310412919618222848",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19224623024423693204198364521320155182851595916789255163194972984385410622619510441",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "209151652029817619220249616172181651341991344670591347824418459106241210604511784",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "03b75a49c7cbbe0bcc5062aeb4f3d32e634c819fce2190c0d76442af15c96ac7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7633dbdb5d24b8ef3d4d058c7affa4ae733b2c65895ea392bcf2b7023ab6c11f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24007b97d8b57bb750613f5012cd180e36cd7232b9014d2c61c1d2668d65bb65",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a3e596ab636bce7ac703dff64ec67fe30db8f63a441008aeeee4662a16c2607d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6f572a17c38bd1536a61b783f8bc954af2ffd7269ff202ddbd6350119a2d2456",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7380f9762a5099748e99bd3ec3b9c1117ea3e35babf1361a5842a4f3507c98d7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c07937000224c233d1670018a4c67bad1ffaf4f23e9d34f7b3d405e8a4007b12",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b0a577b49f1cb01425a9527791b28636a5bf1b6cfefae305d1edbe2d300dda27",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "caa0a8e92ffe8bc83d669e75943780ffb6763ebdb58964bed3573875728a013e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "214582111491386249191049142111401043447487182182292162375369100148212173649180",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "64a51b5cdbf969a2498b56ccbdd9b680bb1ce1306d6f0451cfb76e9eb07815c1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3216928121471384067451542491632451377414720110970797067163126223296918017924644",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f603dfd7dd9a1da7a81261d540aab30d6137320615cc43799c4ff27c6867679a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0ea547f310014291ba97e57bdb9f91f0bdd994cbbfd082199f5307445d1f8ced",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17216108157644562396189287617914474039177671504811237178170436223912497238",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "28a6a24bfa990c567788a5ad77a73eef94623ff98354df950c9feaa7ae14a2ff",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3cbc38a645611f6c44d7c1328c827c94e480e8b24a06a58eec3e80ab68835bd2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e9a8654f4c4e515661138e9e785186b4fb9dc7c17746c7e45df54c0c50677ded",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3aca65b612424af99b2d30dda0f4979f52ca26f30b0a1fe16d5015f21ea41421",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2b2fe0a1c0d9fbde6282b806be1d4f70d24ccacb18ef3bd8a7dd3e3f579cc0a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15102133671621211912401171551042197922821137222138659188234104122821239368480138159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e6a3a3d3a9b8023dbd09f17600015ab20a6d27b406bb8ca95c029daf15cc84aa",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "929615723517224323510112316618687220913659921821855427391261151801081423323614745241",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "009e6628225cab0b9c6e23c45dafed6b2d0a0f3dec11a766acac3ce732c2bd64",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cf18e03ce9b409613116fdb7decf4a67fa124d2f96ab27e17aa1627badb2be76",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "36181172163107722241588450931671491872532042092222502874157238132551681942817224518",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "de2d83e3ec5c6f7d2796f91668c4e3085392eb2ab450113ea73c057705770f45",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "94247221102716662121176207251078724218552376411111016473199163413914611121877250191",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2130131231481261122047724216121976255203144232199232952421095473201068079349573112",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4a5a31178babc4be23936a01caac94fa53797421a908032baa5c2adda657a596",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2c16d058cc7a39258db80b6e6df1a7dac269c4dc6fe59d951915177b291c99af",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c27bd70abfc5927e8969ed543730b26cdab6dbe6ac8e120c11431cf40d01781e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1346911055259613116213841131666241492032551851302540117166164126581891912123521757",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "161175591012247419079179391732141601533527186122535129148112281751146710995237179218",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4471f9163f60e561d9f66e4402053607bc26f74afe61a372adbcce583655684b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "392eb81ca7ebcaf2e28e333dd6b2ff92b420e66bf5d13fab4dd01600dd44a005",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0c099e5324159031f6146b4654432d7ab1c00b86add0283a00488e3ec4ae4fe8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "54c9650750a7d6ec2ffc693029a77e1ed4ea5b7d63f0af94bfd5a4a2cac7b92f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "862001051621361391625722418525724262520614519213512812411513110120718087334811240",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9edb0b2ed5294025f9ad920019490ad6594a4d8f9ef17d23e0738a9e378e3de1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c00714861c947ca169b3392c46250e695f5c79be5fd92ddf180d87cc7b6f85ac",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23136122114192231135819813317551185571312117669802011218415010320518616013036177187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1172321287819220185394814023416112886401181861692089712424472208208108151117240189236205",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bab6eac5d24cf025250a7afe834548d9587b0ab2c899595e13008998c7469a3f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20222401123542134641148061255931508311312311325210021731202753285171191173216193206",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2071211552714922023717217024795391561721024024335117113831402482011571712397959137233233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bfec6455c63a3e644c38d70a49564121660d624f87f3bd74d367da8378332296",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "94f98e0336f3fe6eb861487ab6a4657ba5566c9157679f1fc5e549ab3c07e2c1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "793e2c3f723264caee9519bb98763a9ede78fd7e8331ea8225d37bb2b2767407",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "01a9a5512928bf7427e162054de605d1b4b9827ae07cd60560a41fe61cc26433",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "182091191741341521301153313078176189240592171477319517451139239741352182008710516010276",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5e36542a9a80f92548e47ec505bc73e3305d59d6b084160248d369a7711b58cf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ac3615ae0993de05a066d563498ac0f3fe275201d15faaf298c1af1e0ce5b2fb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53dc552a8c45480cf13a1cac5f39d84a809e84b584acebe3751bd92d4d6c86d3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15320291298910211237223325248423718012361981748918721155871957091182389225530",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "277b0fb600f1d1e5ad0573c5e8a448a5762977afe344ffcad3b94b38478edd80",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0e652f36ffdb7aa1553f9461f1022baa2d9a7d79073006867198510df751955f",
        "optimizeResults" : {
          "modernFormatSavings" : 11964,
          "inFormatSavings" : 14172
        }
      },
      {
        "hash" : "174180702612078240851281902052033722224514077221141104188208195229241218219248157128132185",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8cfe79724d4a9786c924e6ba2fb004c93520c88c0878ca3cf2a459412bf4368a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cc03ae4e43864314834f0409b48a23d39e18235ba7a2e1074f7a5767b7f75f16",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "70e0d4f9353a2b10c7073409d2eb00974b7e53e7154975ee2ff751be1096e57d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c5be1b77e459df0a17f8e1f318c29667609c4b69175b86bcd9100f6aa7d824b4",
        "optimizeResults" : {
          "modernFormatSavings" : 11044,
          "inFormatSavings" : 26397
        }
      },
      {
        "hash" : "9b78a02cd90a5d183b2b6c4610cb75d1bb155b6cf7cf38bb43eab4ac5c150ade",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "60467416110918197912151771629110613426962088920312490233208216146146731312454522624",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e4be7f1c04feaaf8b0d4bf0a1bab81f4afeba09ae59f84dbd8ffc6fbae3f11ee",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ecaf255dc2a7a71cc4f967e37b07fd8540ef925987649ca60281dc59d92e28e1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8693159153252221792232322511324134242547422537619152651921562412066323611310465198",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1141601667824921460229402252022031010521831481563975169161206230206143641034813421996",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2e91f2016a5fc0e54ee492f9a64fe7a249cd65f4a335a1d4ebb595d8dbb40e2f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "81505240c5c9c95964e627141dc2261442bfa5d2fda313229d694349be69f165",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "102771406324770192242111983115847654104102223865399180451882172418124719680553",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7f12c600d0c3ed0520419c394d9d23c938dcccd53a75d9e3e68caf84479875a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6217771462092401992241261147239536424114945154904115024418122311217121082172408523",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8de0d37b352575c1dd771f12f25656d386d8d4450719bb8ed25216d68264c3e4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7e614ee0b60a5abf86487e320c582e2131d4ef54aae3c82e6d6ea2925ab92b21",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "de176a7afaf2438f374ddc69725740ffbd8ad262a3b0eec2d4ac8f57a6138d99",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c864bd621402761fa3ca660a5e36cb94654741e4677b3e1d4bd0ad5bceb73c49",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "98f57b5b09d62fd9a807a7a1c3a08ccae9cec8e982ba13a4f7987449fc13202d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "791f2afe2c4aa41e111076ffa9a1ac92c660efee6547d7d8dd9481697e9744f0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1501434120171341701462364616558318556122531345227118111618715644189797341133159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21c27fb36a588c36ad3c450c77a9207d1a39d354cf3cb2f487c6235a05acb3c4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "db83066c28294f8873c23212959ede9435ef55311b10ec5f15629b830a5b2f40",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "671341793218320995672401682104223576381142617524955220691727536722224418919312445",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "132117191224152951755446272398722482208223351611723673441818324722010217614014117098",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "752f74dd935b5973992e28cc43dc960d699f82ed54f98b23d65be8aed0cba4a4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2322512878123249113602371821307224215218495109163471692412557418124013411013822147148164",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "48e2ec8ebd6514f86ed005545f181d3c495f1f6fa8a9cbaa2b76266160c1d0e9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "95d6fc4ee91b67e9955b328c947879f1bf04fedea50533e71f07222d7b2d69da",
        "optimizeResults" : {
          "modernFormatSavings" : 87450,
          "inFormatSavings" : 86250
        },
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/samlp|OKTA-DROPBOX|zacw@dropbox.com/324f315f-0cc8-42e0-99e4-42ad0f4d4b7e/blank-photos@3x.png"
      },
      {
        "hash" : "91e66c54b02cfca454b91b1c5b9193c0be61b92999e89aff5080a3462410e2e8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "acbd9fc8885b2b94323d5730ef28f2946ba803cf6d13e49cccb1148e9612133a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14023960401661682492504717114550461996492155234102200151824354142160167211352455",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71051008716395153245165158082249431689611999637233132302588556136224232135218",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7340a1415648a7c4281b6064687512403a5fb556b12289f1da71a8331a4770ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16d367ac094df797daa42615be7130b5dca198332f6649a8ac57ca5a6d452bcb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "104245117311181022457423701133622824113123199322015616621687103166654329249248116203",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "74b820bc268627d357ce195ada6c309fdd9d8faf10418a2670cdf7ed87f84d0c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5a162e2bb94616fcfabd6e000c9caf96857e5d65661046026701809846587966",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2d096a4b856f3a6ef1d2dca19989572b92c02555829021f76bf2993fa651daab",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3d2ab4022d0b7b29036fc2c1f3b9f5aa6f5814b03596913288ec03f6f71f0282",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1491579260190711402712418210619917992112353925118915823814774224140226208100153581237",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bd81a3a7c09daa8f7be3be7b929dd9c5f8caf708a3cd00a6b6f527c613977f94",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ca0fbab9d726598dddd99c6779362938949b0622d79c3d085d0476a39e4984a5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8313f711d0dae7c6e1a33cc6c3512d05ddd894f6e22a3e889c5592aa54166fcf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9393205181236171201981411202411702501531684118227113172225165105105224215351661962213984",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "215209238467232173184169343213225015115815896642059119887105571946885236143175101210",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f6993ce5d224212564ac376b299b5120d184ca514988ab89a4faaed5a577a09d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3fc3afc29e4eab286fbe37fb38462f6699a41d3fc30cc8dc8b161fe4d70dae8a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "140eb64393187118b1108f1955bea44c8da3dc455329985b143b131260b5fe55",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fcf2aa270bb1b0294b8316f9a88c8809598b94893c3f38c9ebc73c3969af825d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0b7c456839ed4d14ca44a886e2cbda8163561b6b68841a2a9eac74441238f057",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18224522219441168956022413071131240721576401271276019313113025014213126737810625463",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d776bd88dfbca362c5e5593ce85ae02345b8c48db9402d86b61fda32754be08b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b3ed0de773ad2eb843f65d6246eeaa3d762811d707a31e494d816cd46fffd491",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12588198956916023720815862564418873208129176246154103282224613818424124182796411220",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b630663b871689efd812a752006c354438f6e013df3066f7168b4129a8362572",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "956e9c32a0eebd25ac44e9d5de3a7d67cd8316acc290c851de037d6a9d6ccb79",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e01afffd99a46353e83df51c67261e41de0a03d3e67c1d0eed986ea28196e669",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9faa44811890a5cb48fd968b0f5342ae983b90f046ba41e8a7e91f65010a2b6b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ad2064c60781fc24760e244e15f9fa0ebbfbc6856ec1bf6e6ad0bd7391959de",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "152d6f2b20d589f4aa1a86f7e593070b9d9067594e58efe2db7f8f81358b4720",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1533a65695e77248d6b0122b173610edc0d9bb9bfd08f29f91f7e56297704341",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e4d7a425c5505d7d5451c6d23d014b99418e3ad03318b18d2fa03c203a5bd31a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "203116221641505213241541834372541671718597251159362226569125742311521912256716176",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b2af231db69b5de16ca6a5dd5bf56e14b0f5ccb745b3f37aa6a3ad1e32beafd4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23925682163320625184246165143772101752511211301524450222192153188441181961806733180165",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fe4eccd9d9357f94f93c35638dd2fa2c1ee4d39589c4940198763c618e1c5e03",
        "optimizeResults" : {
          "modernFormatSavings" : 21224,
          "inFormatSavings" : 13613
        }
      },
      {
        "hash" : "cf579809a84ecac575910db103c905540d69480174ba08f4b4860994c249cac2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "02b57fbff14cb0be2ec3bc208c2e486f7c41449a2d9ab56d9de65244dc5fbf06",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "68309d701764e817d19e44df667f5ce10618b9b49463517b70aed747412ac1b5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c6fca1ca79e4ce2b3edaabf78cab1d20ef80131819de44853d3300fc8b08ed63",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3f338843d7c513432096e3cd4b23696b02ef6d68a5d81e1cdcb8c24cd132d24d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "878f93c9a06363dd1a8223456dfdde841f66e08a0c103330e52ad1ae509d498b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4d71de6e0d856b6d804a67516f1e47a93c64a79489d4bc93029c4a24802f6e02",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "59f3c67a9a7bf62c01c1062958ede592f7aa33ba71306aef06f7303a8c606690",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10c074f1aff8222095d1c7bc3aa67a7a65fc3ee801a3be4e8aa76ab4c355ccdb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e915c020b8f4224bbe7715232517366c1f59bf857b476e6b637cb2088c83c1da",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2ab5fdb5535c46ef017c8e5568954b84672a00d87a17a74fe38307a8b263db2c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a2ccd398b619884e87f0a84708c7211d1d74a52dd0251f703c67cf5f5b65d4a0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2081232172471881601094352871071716029744817815224716612521935681721592118243171245184",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a45fdc721e00d654d2255c8633323e1ef47416074cb1710455a25379d67cf204",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "82f38483162e8f07b366d88a54929c33af8bec2cb7cbf2bd954b984e0ca1d60a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6c820d0a3ea80fa6665fe5961d5b314a2fe022c0f5ee6a9d3ba7d7a63372cbd3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f8cc6313d463ee0f8baffab5502d3058fdbeab832d5c2a4251def8482fd97a8f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "659f2f24f3e935402639e427285bf462dee2cbb2325c27db1db98681b9ae0d6f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "98672011181811126324420880641856416814424976822231914015423411724383231902358914317",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23215020797134952291741031441574209951874824712822093952036237669315416141140101174",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24e7b8cd04b822d8734eb46a1271933769174040f2ee3d363325cb5ea2b8a2c0",
        "optimizeResults" : {
          "modernFormatSavings" : 31996,
          "inFormatSavings" : 18081
        }
      },
      {
        "hash" : "e57efec5e03246c2069463bbfd36b7458bee63811ff6f2ef65efa3a1a408d881",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "61229ba2f3c3e022b671e0789310ed80d2b6748cada3c2cd9a7c03b6bf2b557b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "472886734613121768234252761299112641154771152432111451881543014215171123222237125",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "902fc2bf1b2ee683420d85d0c63d1e7509a9283144585033d5af232efc3deb9f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b952168a4884a7770e5a277fcf41f6e5a2880b04dcb5a44ed685d401009d1a0a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1992512348599812457912316749137160138207621925159712511585147254222182383111593",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "867f51da0f02e5855e6283d7e331804a54c98f3a9474ce71a3da699d68938e6f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1412319497181195182141168251254182102412910858731001085262203463211988110237196172",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8418821161511202101141891873819361808225079124196428815716402109365482203842193",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3f66510089b18b3877c97580bbf3b6e8966ff7543ca023dc13ec448eabf3e9a4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c8df592519b9b26220ca6493e16faa44ebaab1da343007fa4c7d94d428cf25da",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d414f3e6aafcbcb6602d1da95adb9f1c7c2d84ec21eed10739a2a49d0cfd62bf",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0517478b5cbaa36893ce190c1102133decb399a47aa0dd2d7978dab80a25e58c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "25112132160164714260224848201864220620134253461391991182248053128989246101131207",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c51e972e0e0f41988d1bf46e75dc15b7bbac5c3afd8252b6e3c42e4bd5fb7499",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6ed9732eeb55f5377064d6584dc72902756b322e515263983595205ce24fb99d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "56535112238192124118931291364417620823013048144408616517918816021421324745728115101",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "927542a71dfb94ec49b917891f450f937276438a5c3554c766e9397dffe2421d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23836b0469fd8227c3c4ee919ecd99d460b165f79c2afed151cce08b6adda87e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "547100203222213231693190252245206464622116128631511436724911201311791852367108",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "63239592141841954310717974672531412001271171061135088927318067422362268115107105108",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e66ab2623331d4e33cd5fe01592d71058425aa2127d3d706479ec122daaafb18",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7b158ff1b6e5f3c6b723e39bec2c864d5c27f011d4102bbf02860cd9477fd8da",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7f82fab07626792f40265c1ee0e71893d771062764cca0c5ed801077318e1093",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f3f195159bff15436b009e496fd8c606ac53641ba04d301c4dfb24e9f64ec7c2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "56d174df264cf86c9011dc8b9ed0eb2f337c99323e5ee808fb57fec5284804e5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "835586b4b9036526797c616d84f12ac7ee096f255ee728b79348fae79e4d0542",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "235351602061561991601915011217691462202521291721247025042509210645406725045136129188",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "47035d0076fdba0235b60803fc87fa1b1cd84481fa7a25b59b2b9f80f6a23233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "212412125520324917417132249211201212161156134611551416720051210117152342248491527076",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d1d929983c4d67044d3be2f8cd123d62d084a7d1d1ad24890881d56051bca4f1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12814023526579177250202135952792636126186197618396517522212410183325553135142",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1552222122411327922111019745113203176251182152917010211424734913383976524924826117155",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e3fafecfb2abbe27de35d8530a992678466771769ed301cc5c8228d113af752",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "203175188378085157207135220178143478717521928170206442511562292202072061610482233109252",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "58738010210718990305784725123917154651482371882072582144211891751898821818417240",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4118368e24014ba1591695a7c8723a03468bb497fd1a0bd2e8d700fa5daf06ff",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7f09de1f3169c21f8482228fe27d57c86c7624ad2236d5e5c6382f422ea433cc",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "78018358a280ba5d379b6e0484b85de05fc537b37fdd46cea32bf702644a97d5",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19616013411816899195198148981269752834512740217151546322415020410515090145247222442",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "91705d63a7deea4c6923deaa5ace58456f6e54e921df70f383a07040b105c276",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "998dffe8c77bbd0f0be46caaf8b2eec765926e18fff00013671f70c6c04a1f20",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3816114620976254239187246232221965721020222818917145976310212169108401327691101261",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "28116c6f2940a2ea3821888c00856a051a001467313ed330447096bfea5e682c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "165125147130531991422352451981014713221313316561481852042206266515863632472052377912",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b675fcae58dd7660eba56ff21c0b904578682c7f88bc2b663a1bf4aadc271ad7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a809897426d41f5fdacb801f3bcde6e87a61c0a80fb76dbe9159ee48e0cc84f1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4aa1f277d09f023a767adae8c9be0b2dd298560dc042bc249b94ab78a2702719",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9e9d32ece29613d667e3ef5db2ce4e00f2735daedf008344c5889225a41fe66a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "af67815a7a3ad892e2f1e19f09fb0816a51e57064ea21adbd1e8c6331ea8cd7d",
        "optimizeResults" : {

        }
      }
    ],
    "userId" : "samlp|OKTA-DROPBOX|zacw@dropbox.com"
  }
  """
