//
//  File.swift
//
//
//  Created by Noah Martin on 3/16/23.
//

import Foundation

let amexCache = try! JSONDecoder().decode(
  CachedOptimizedMediaResults.self,
  from: amexCacheData.data(using: .utf8)!
)

let amexCacheData = """
  {
    "appId" : "com.americanexpress.amexservice.development",
    "optimizedAudio" : [
      {
        "hash" : "1077174110229801140177443812066159971151531222291542283834156992531241749213614033",
        "savings" : 0
      },
      {
        "hash" : "2473023135155146122163377251412301061542292996416912019734208122178103914524714931",
        "savings" : 299,
        "url" : "https://optimized-images-emerge.s3.us-west-1.amazonaws.com/auth0|63da7dfab124da2e44bcf1ef/62d9d695-6eb3-4967-ad78-1eff90c5e34c/delivered-Converted.caf"
      }
    ],
    "optimizedImages" : [
      {
        "hash" : "4711924111138210207156175208562001732181391272201111952443820551272171491591421259496",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4019823909721115017425411712082062394717724010820720316121215725524190219154137233139238",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "082193b5ab43981d485b597b416f6f8c80a7e951d37b1c558f47ec8f277aaabd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a36eba358d2ad5ee0a929e4ca2831224fa0f641d41ef7b64ce8e7adabbfbd0eb",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9a3b1c06791372d03fabc8f96bac73bd63effdeb931d84df746a4feb9b0db732",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1f5f7a12526e850bed4cd63e60da5c44bd913173b2461ce2e52729f9057904e6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "00866d663bfa47129f3ab73f833756ee3f0be801a14581fc0737b80d5c23c199",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "136162312161905325130341366711125415730125244623667584787174183221142311911217835",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a66b84cc85d8705b4963af448c5fbedb2254369ab1b5b9797f2290a86b373e55",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8461048815182151186155871159711411185150152234767255421217615657236081995611",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "311951512121415619114617927234139711481071027108236981771081101421612429221663234160",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22761118213165112916617619916416615313821312918314513211785371291651242021072132317493",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c52e93891dc6d657ba9895003562131bd106c1525379fed94401784f08b86342",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9cd51bb4e80d2ebc9433160a7a02f822f8ffb6f3c87bed8e85ef02e5cef32ea8",
        "optimizeResults" : {
          "modernFormatSavings" : 48784
        }
      },
      {
        "hash" : "8ac11a75738480d28fc0d8b74e59201c4dfc653b0c084dee1ac5e5584845f853",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "13b2ed11f4284fc4af21bb40b9150b12f91addee63c378ea17099da856cd3a42",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e08f5803aa28f03e0c6b63de8a963731cd7cb0ab5c8a7dc88e2465cd2fab2e56",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "601445c1c450dccd087c2616d1416e428a44edc34074baa6a32722c7365fd209",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15ad2ebf316b0e7bd989cd3d299eae86b79b1122c9839383b841c9e8bdf0ecd8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "196ca739e7f335e15ac979b71db1badc1efbaa8854f8d35516f4b77163786ca2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "42204512322081031171098070181531972075911192863448104421101026317233234218160190232",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a06c0c0e82dc7aa3d2b95fdc9fc0034cfbf531acbd60af066730226345f4c327",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4f0fa1eb9e966a7a23d1d955ed653e22810cd187eea6b5ecbd69e8a62446ffc4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f5339420bad8090a45a2af78ad3711389e23797a21ad5943245eec10e54e7b4b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "636c113dc58cb72f7e6e0d64d7a7f259a9fb187cb780689c895cfedd67e53390",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2201d489967a347e18114df97076e1a5f3167150a2d2b55502cbd04534d4f637",
        "optimizeResults" : {
          "inFormatSavings" : 264072
        }
      },
      {
        "hash" : "9229116972505481926321418123692027919325248202421815914319812519423721538156165185",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21fd7b96f8f80ada95a982c5f0d9f2250da229a81b7df826c4c764c71e6a3cb2",
        "optimizeResults" : {
          "modernFormatSavings" : 363496
        }
      },
      {
        "hash" : "6d2367b290daa6047885db9ef834a9a8a52d1045cb18bfc91df9588421a44a81",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18621022841961172023624714115722191486624013220100168103637248102261782499570214195",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cfb1d54b33e4375be4edf014eb15164dfe871dc4a780ce3b4b721f107390e5d0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7fe614e510100bb4fa283717b3522f32c27641c1f107cdbd8c0d3c321b6e5f28",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4c0e58bb29d8016eaff114a003a9ef294c0c638a08cf751dbd29ec1e69df4b22",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8d9a8e7641a03bc6cc179945cab520a7160dbd3d97d71ae4aae33ceb4fdbb31c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "281f256a2f30b8aaaa2dc8409f09703f5861945e8ff78441f4ecd595b7d93a8b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8a506674f1f4865dbe8eb42a454e26c39b94c6fe089612a03b42732c1e235f71",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "6132485dc673f1645076519d7a9b41464bb1067efbe1dace46e30bb617a3cd69",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1512497587410110515321113821112225213319818418276229521819716416215521522024112317111119",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e45d88aff6c1b88c2115f1ab447f7addf0a978ac1e3912441881649f40ed647c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "84b21380c4dd73c302d9f097ef82bb4bdfb5a9e3886da6d7caa5364a95fa843b",
        "optimizeResults" : {
          "modernFormatSavings" : 33156
        }
      },
      {
        "hash" : "4749dbf6e0aa7bb5bf3a78e2d3598d721c6eef91a5362fa843adb16adc27661b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "30ca120d5da96ee28f315136bcecbbdccb464c45a12fc27318b1b13a5eb6326f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f126aa93ce6bc5a40f8c0ca3e30ef2aafec093124ffb9ce5765c5b8df13157d1",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19799711272017723719113180113234753015743296517212613122992315813810713124910997",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "592b1c33c76356cf2e3d80a771dacbc7d61ee2017e6d03220d88a0f979407772",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "297da8924a4c642e77e141d18e945616ce095c1c5689a148db8fcd96f0dd8292",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "168124135186918837213114217035136179301824791118237189188335255205101475117710130",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "91dbd29fbae878199c7310cd8872de4a3ba5de5cd4851a5a8b38c9600c708132",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "10525345511001534933132922441428331233715821817924015311745650895415113022170107",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "baac81a35c9a9fd448fd9e514446b3a959dfcea13839a170c048d0b3e2488697",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "15f297e30c75660a31dddf076528306de8307f5d28111341ce682e7bf65a5cb3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4cd8fd2cb3519dc8d0b5956373416f06ae1fdbb225bec65c056d672f94021e0c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1511762151004724221963438121245203182252482312461923913712811223089135747153767747",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "751231197176229120562531368523938190121129232227100792510214522365629216557107",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4219758201761541321382112334242195774827236228147670261352110020087227167181244107",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "75937c5c915e2eb47bff5f07381ac1e5d8d6bc191e1ae3946769819a31c172f9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5dfb025e5f08939b0e82d81603a015344c9bc645d4f3bff66cd88d80de221091",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3115620471331501433510724523510717805498190250365620670141351451861551383319377208",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8f796e6ad2cdc51a7425a16ec2bb362bc0e90bca9b520434efab43db92355294",
        "optimizeResults" : {
          "modernFormatSavings" : 8456
        }
      },
      {
        "hash" : "20720923165016911592421031856162121329315623116519824232214131213957744710812943",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c5af0358b3fc5f1fca14a33113863ad9a5956a2583f6f3519c844ac7d2e71a60",
        "optimizeResults" : {
          "modernFormatSavings" : 144043
        }
      },
      {
        "hash" : "244209176126677224012512853185245683028451012293243992273912923114212510716510724539",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e78f041b0b398c99da985de750d96b8511cfa8df324861db33776d3ae4ee40d6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "56db4f1e32743b84cc57cab5dbb18d08b40385d78c3189a5cfe4f304aeafa9b9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "291939115714218466225240275513191641542112424010416810944114952262286119251412896",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "7792e068a556b814c453c8a7dcb18da1d4f8e34d537f517ee64745919e671464",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "200104722021781734018616218130951561261717214071656824564818572191155465614111126",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "200286758208501211061791644618318622333828881121128150375366103532092819898",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1341871261461918923121022512923147513127228246227113150219238172240241298620111376852",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1972471311861842151201265776100134199468514912071974698121238861892322519423310250102",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "db01a143cb2b80fbe4d2e6ccaef58f208a407e7fc6af1e103c3e1dd6d9cc5b18",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "b4f8aa85dd424c66b4d0912dc90ed4bfaa95a6ca1838732411d44ac66fed667f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17813961829213513112616719420992351726322918717466971281811712221061591122425310067223",
        "optimizeResults" : {
          "modernFormatSavings" : 20036
        }
      },
      {
        "hash" : "d292d1053dbb87a27a3b9fd6abef452ffbc8e624a4606b95543ed79e070d841b",
        "optimizeResults" : {
          "modernFormatSavings" : 45769
        }
      },
      {
        "hash" : "ba05c4ffa15627d3661bde04fba8e4510f898a66d6aa831df0baefab42cadece",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9a784744ba93f9ece90cfc150a2ea438a425e61c8270491eda2b05d57886f923",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1796871118174170691651841462445420392445201993942192845210119255206922324525511",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ce0252a99d36bc415903f37f4436b07a85ae049c72e19a54f0b06560e638de10",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23315428252236762481931397836214137119198136111239651821531872381165135991926916659233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "20944131104829531071219442202241248125175242143109176106149103154107951692251632470252",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d6f02d7c97cc650f5bb3ae9858fedbc84db27788cd999b52cfa052a21089ae2c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cb3a8c76d697a6c9cc9600c69c800497b1bd66e1f80b400c707b8742254203de",
        "optimizeResults" : {
          "modernFormatSavings" : 158738
        }
      },
      {
        "hash" : "07a5e625f3a9a39418ced3096e3be7ae0982c8e6aaf52e8d051e7c13656fe3c6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9636d137fd2e1ef8b61f94391f47cebefeb3417424e0117c1786c3631b432ce2",
        "optimizeResults" : {
          "modernFormatSavings" : 286441
        }
      },
      {
        "hash" : "24315224819319358222201207131301432479211836154332032133620017699202114175219128190132",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "189187251772516520199203190211321091664618054210179491152071131972311694013412674146",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "85712381279219914486212176119236209109151128166842152271561131576821487416967209190144",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21a1074ed528b4fe7e9145fe5181fe823f6bf8a80c95fe616b157f2c99230825",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0fabacdb37d940dc797a97ad72dbb88e13cdb314986bf9a952fde9b6f91b8ef6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "65ac1d05bf37d275c581f5478fe09d768f2b57cb164f71f8be3d527ba80a9c2e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fa42a9c466905fbaeded55111e12a96ebd0a89a3e145f6d34745544039b79a21",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2516423017918846129144212041811791421082502184725192722246317117263249212219642496254",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5710923975321875523921579421092257271505517817223022821455715921413530102100230128",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d8d08bc3c30d112decfcda4c4d936bef0a1dccd550a7add8b8c99203208c2db2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "53a81419542c8fb8bb116a7c96b46ce7c968caaf0145dec71c30af7261909b94",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "25163617110252151865625413262191545515319924815715184249246541151722321852071542912",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "062efd1d10ae3bbb80d802b1dbf905ce1290bfc87dba6de033e98589af8b0c0d",
        "optimizeResults" : {
          "modernFormatSavings" : 265878
        }
      },
      {
        "hash" : "fc0746ee27ad756c049a07bd550d003531a44075d3268cf1df6488f0d8b5ff79",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "45e25d07b4f73c4cade2e2cfb7462890122ba90b8e582323f2251d4bd38c27cd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d4ee3cb7666bd6fb327da5a5bf8605499b0b75747e9391044ce4a7910b62059a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "38217199191621716215699285510019617119681542721516514716810814243485729494215185",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "19415912105491120322918723511015010178250107233117512081214211817624552591621008165139",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "159187615320525311411017214123629689125115381205235972421561562007323223181233154134161",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1406064130152973112182862462029127547016477157019863205451786200155132204252137",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1006622611416124745316219217724961531904715911213724513612220258174241117186787360223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5a94165893330c143f8e803af5ec61d05bb0187e34f8be23313db3cfdebe008f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2019a04c01bada72c9d21d45de1cfa383a78a55a5fff44e24dea1df3bbc8a60b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "24718184561466071652409614012687139255639922018611310283215190176176831871368937121",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9a4cdcb5967eb77829a825c7f6a40b8af98cd4af70adbb19039332b5ad3ce54f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "cdc5ff516a3bd6f7510bbf911dbb8365a4e8648aae3d66576e06725ba3b07af3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a7d79ac1e0e8cc7dcacf06c15cfa6c75c66d069df78b4468b969e193524f90b6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d67a1bb841aed86fa11c2354391f28f05b355fafd331544a58bf378102ca37df",
        "optimizeResults" : {
          "modernFormatSavings" : 31730
        }
      },
      {
        "hash" : "fb78d0467f9f3aed56095a0c9b3dfcc1dc8d58b86567c4ac7930764d2f635cf2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2241555216911782232041217913521064155202074915511355262375615673652172111309511533",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "60c366c89251f9dca5175facc7726bae404ae11e16423d7c84fb235dcb261976",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "205235551205242369620110014797196358915444151228621929426160764220273109149162187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "3d35205df21d43bc9093f36646a1603d418bc4a094d23b98df457c8c31cd4548",
        "optimizeResults" : {
          "modernFormatSavings" : 101548
        }
      },
      {
        "hash" : "46431161716981396851586215910822132238442055718192232351572522301649611282155",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1504550281991832512424223413417932333118331362148310812381501362241333916183251124",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2122341155951961701301172535814591175220235622422012352164525132341185231",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23925124014186205142239151102371131222462685146337754259244661771622960218187145166",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "421371131140424429541861597571319113439624167123154121703523118521517523181",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1cd33c21bd1de2951dfead96d079c388bd74f62bfa12f72ecb197a74d4b4dbbd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d7f0a71de1827c66fda31486c93b0b4de117a13840726a67f6e3184f41aedc69",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c890656c8db47a56faaed2e66e83c4b97ada4ae41dc3ffa7f03e9dbdafb957ec",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8fe5a2e68ad335ec9d0f0ef6dc9dcfa14503a7bf10827bc706d75adc7734431c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "201272521382171591072312516672252111162366218422024913512281181152442369418520666248142",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "101841521311222855242631139218112015124828142164124150130216244251170772361693519823572",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "61244621318314917415717112017049811411898717118122253231082441495728218240246184179238",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e88604eaae6584dda24cfb101f627374a1547364170c4d849592552db87b877e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "421b0899067ebd52ff274b93a9d2b4cd316351de093995b5c126eb411ed90aad",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c5846ee9823ecc8069768d0c8d8eeb8c422c104ed8bfdbe04ade9730afcfc822",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "628029dd1aa04ff8e0578a2ad7f1d3e9470748ad0ea5d565306077a2d1b8160a",
        "optimizeResults" : {
          "modernFormatSavings" : 223787
        }
      },
      {
        "hash" : "22316617224979787262183875233171102411622303373116352852196143228251154102492234",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4ceb15ee78257f1458722c65751ec692f03d1eae1c9b61335103daa91459b949",
        "optimizeResults" : {
          "modernFormatSavings" : 109113
        }
      },
      {
        "hash" : "a6548548d1c17bf8df1f877ff69d1aea44050222e687520f21b1a1acf97ac303",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "dabfcf35cc91c97d6e10fc3c6c72499b503b12683c436c9c6f43b1a9ae964a32",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "131230235239741472251066056118142449739119154100141130213662041762131111924323493237122",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "e47c64845226787276f0331998b2fd9adc4d039b2c3746044ef02acf78908108",
        "optimizeResults" : {
          "modernFormatSavings" : 14623
        }
      },
      {
        "hash" : "6b8aa48233182c7dddfbb4c19796001c298c3bddd3d2afda298dac48ff34a4b2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d57d8e7024ffa71e7449674f978665e2eb8a8b5c01a0d2251fdca793803d9e77",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ecf4876f359d7bc9632ea9c012aa728f051ebf090a60d830d56756846d3dd14b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8797220101184147171219643686203992139205182244186220113591694841681531791328175215",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "821812414723616517416932205101238231306717612170133178187299911181218226240110231110",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ee647c67cbc830d410f0c346d98ced180b3bec5c5fc0c4dbbc3503f55ed0b833",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21350139185225218717218424221152881718396118369171196613865216352010412111018140",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16624719414613714919215710103737182171487193102731682655210235941852492411601881252",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1c952c0558ab790f8111d325a81dacbff322535e5290e51a8e7cf52fb987d8d7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f54a30d130eca1df75c4b33b7082de98afc18ca00363c6081f7ee06d4ed68706",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "a5455e42819363843320ca911b4b5219542cc8a6671d8cfd98eb9b748a6ed454",
        "optimizeResults" : {
          "modernFormatSavings" : 213894
        }
      },
      {
        "hash" : "d743884d77c475cdb8b41719a2ac766b159790beb0b180b3b80d96e876a6cc28",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "141232122281431586177184522475872101177117219208501251131227108335682211613771",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "17623219716211712613147662381325414737164173244461781293619215127156448159123245167",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "40b8892c0b36f6981d9545d28b6581f2f2dd0e3a801046cde8e98080da09e969",
        "optimizeResults" : {
          "inFormatSavings" : 134197
        }
      },
      {
        "hash" : "c140030a1f468bfcf2197b90d99bbf56212e7fb5a343f361fe4fdf7c15d735fd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9fff4f09afdc73d5fe0beec60a16fb8ef27d1ad46f33343c41664056af36730b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2094824121110822259342381468819019827209148106501245122315211713294492112222362331479",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "06d3bff482983bdc19d038e3e5e21cb7eeee3214dba17140875350aa2e05bf9f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d21ace0fefe76d11c130c0e958213216e5508fba98e4387e00cebc9ae0b750e0",
        "optimizeResults" : {
          "modernFormatSavings" : 287202
        }
      },
      {
        "hash" : "2f432a6b25a0e370be0e9f03e30676501066fd138129cf31829b72eb98405599",
        "optimizeResults" : {
          "inFormatSavings" : 263215
        }
      },
      {
        "hash" : "4824287221202195176871416110484104173177233129186202999025115114248213198152712189223",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4faca2e27d84397efab5e9d28efdbf6b4cbcdd79e208420ac3eaaa637a98f879",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "13494208220567820221614622825264922799180174871212232389528223141641115125180182",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22310620573620415524953213175108105232372295333721481451412313512017912819421177103",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "8fa665046323d9b3efea465c9a77b7346c20ba5ec2eb2706a2ea49ae8e874354",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "75c2704a1019f814f0c746e9f3d2071a3da0d6b1c2cd8adbf0b2d5b4ac9351d4",
        "optimizeResults" : {
          "modernFormatSavings" : 13873
        }
      },
      {
        "hash" : "b888b6c9f1fd1baccd6a31d82e29a1c90f67558d1daaa810c24902b9c7539c84",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9d9f975d9581021d72c2fb3b91d500f36f4ad3efd8f2aebc8a2abfb3fada3d03",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c6e350c22168b4f84b2611c85889493a17a89a70cd8254e1035bcb827ab50e7f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ef4948bfdfbaee742d4210af24122a67a7b7b20391921b4bddc185635187a49e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "821606212822932294143136111381562831361481871950252145143187118188713858118180",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fb33d224f51ec4849554e0acd6233da1c13da2b258b4aedd8f9ecca6d7be18a2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "150135411812371772815611398413522225088603184221091371781352221601280651942324",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "128241512310233417515750227720610119834248133125015023514917611914761971724211187",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "77ccd88546b6e5206c088900359b4bcd249ea94b0c5e1efa011417a0e147dfe7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "249216622531271996762215831445298608585190522464978188382182543119514776112128152",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0c753722ed0e0b82e84a322aed2ba8abec43cb6b86303c38e692de9083b23b41",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "899e94e0afc7503308fae7d100e9e06ef4779442d5f03994a6691a78ff8987a4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "124845436145142211712522102061748313916512012012493165761091038070311772468824490",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "239139616220132160113131412041131531401222141031082254211101228225241144852026103",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ff983015a4da7d6330d29fece30ad711e21f316555d7665e2f23872fd331896c",
        "optimizeResults" : {
          "modernFormatSavings" : 425526
        }
      },
      {
        "hash" : "1f9a2dd1346855fb26a50efa031bc898bcb7a8bd6da83fcc45c2d2d3c3bc2056",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "801531021671832452332125378160191107751781031967020318663123212140225842402352710885",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "22314571252362377925420224421016310014513082861746797206231151936725111282051422576",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9015153b6c28b2e16a80fbbb9c7f6a35a5fe53c7865232634ddbcc23bd73d4c4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "246452194610260143921511120224467423149246237107188211104657182621937218410564",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fc1cc96fafdb08051ce2f678196966a7061ecb5f573dfd2124b513fb0047ed4c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f53af69c00f774d7b739e455fec0ea75415cb2a3cd594113639ee1e0d9a3902a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "feded45417080171426f6722f383dea9cfcf04397abb5b7f5a27c54e5467e6e8",
        "optimizeResults" : {
          "modernFormatSavings" : 152322
        }
      },
      {
        "hash" : "24320623611230168551358425424619219746392482297323671611051077223122441823240224226",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "05b500cc66ee0e4b278de382c823cdc7551a18d22b58d0332a267058062c2080",
        "optimizeResults" : {
          "modernFormatSavings" : 134701
        }
      },
      {
        "hash" : "a0946eebff744ad26d7d85c29ee202e76963694376e615c847159b6bcf79a662",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "304212881637740511311351301901761082222513510115416624621741801972378121918010593198",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c6c4870e2b7384017dc248f2d353d09ef973bc45e4fb1deda0ef3da46718078b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4a2119da0a8b5818212c10617058c3b3bc439af40a1df2ee4f4a82aff64e5351",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c114ee2032dacf50e95995358b38e04de1a40f22c19ef98e7a0ff10e501865e2",
        "optimizeResults" : {
          "modernFormatSavings" : 106131
        }
      },
      {
        "hash" : "d13c47c28316981a28016c2e53e8cbb5e55e6481722836204066a21b55ebc373",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "21110822942139252811862312071821372521492182501645223912716659104502164030981762052395",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f3871908b8aee08194f7b9f929e59648a6a0042cba14b6001283449fdac357d3",
        "optimizeResults" : {
          "modernFormatSavings" : 29804
        }
      },
      {
        "hash" : "16ace19937a3c22402e6696e5b021b3f617d21183bc596ba09c4583d446999a8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "46dc7cf886f7bbb706fc717f49e3eae5999c4a416100bd12187df05d40a18d0a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5cfc5d4f3262e8eedc16829325cc60cd50144fd24036ea813258785c38383024",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "91fc222d2feb813be10a551f42f23add57741807bef478ba7371c15f192dd226",
        "optimizeResults" : {
          "modernFormatSavings" : 36069
        }
      },
      {
        "hash" : "5c04ed486171c83377ee855f4578d54fa238beea29e29ba5f2ec11c7cc335888",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "237126182212923440178160104523014781043724415211821213207472337815816321511931991",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "151515974832391999552062271611676431114208163312062468570331622181961539521914263",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "420a9804f6b0e6e9e94216b4b642cec873e3c2e20c97d4bec985f6dcf1a745ad",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "eabffe01b9df0802e07a16d8719dff383938f6a63ebff1d26a0084a36a246157",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2321436410213315725214860619591224870169254703762162807118797235178529736193247",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1ce3053ced9d66f42a47cb7d1d67b08f4c295b71c7a4b331b83d47f74e457bec",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "14bdc40855e5a390545703fba53fcdf7aecac7bbdac9e0edc3adedb983bc6bc0",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "928297fc781e856586a85f42b65fe6b14eaee64a062388acd4cddb8253e552e4",
        "optimizeResults" : {
          "modernFormatSavings" : 33528
        }
      },
      {
        "hash" : "3821012517217022146118127120139163772301462072481894817024219762083289699174485162",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "12219489163642082543261124100222102922528221549450162192931624862251105242148118212",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "200f5a0742aa9a5d0590424982a8d45472468b6bf9f8899c5a70f4ddea1c4639",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "07bc659e4f0fdc091be9ad6f2814ba5e82567c3549c849f29658261a4657df3b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "25ea152afa8feda5e185e619a4be9a95fb06c91dedfc422da4188cc6c8559de4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "71d2673d2a7b5f5eaa8440cd36219fbcf15ec28902a9867bfb3b3e0e91fe3815",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1640e6650b5af3574a88f1a76a78e11b619d73c67f0adc67566691527baf6708",
        "optimizeResults" : {
          "modernFormatSavings" : 94799
        }
      },
      {
        "hash" : "ef6db6f46266aeefbcdae22cb92e8c48b7daf63124c41b98964aac281f913e5e",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d833d132aaa0407282f945a3ae541dfcf2454f4a807381704342169b8bf69bb3",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "fbe70298c317f86838a431ad0c9406270adfbdfffe61b04746ce999defbaab16",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23224517376106777254633898204216165871582139716187341149152541066691825552197",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "180141591716815021112525514783632158129234196551343196194188237281832194751204100159",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ca5ba3e1c20885adc5d9cef43307460a20efd869330417b14cd07748054fc0cd",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "c3aa1b465009a12c2207b49b6106075b3550064a8b61c541d069dd2474516f8c",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "841717714610722511317345151434387214205209100110171166547579110518167190173174170214",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2677f3753ecc627c0ea8e09e9c0bdd2c00a91c02430cca68ad91de4377984360",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "572497515190120159021741591232372121085414614024524611422612411473982516620123865",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "f0602d810cdf9a87933b6454dd4163915eaefec31a2db7d53e241ae58283ce81",
        "optimizeResults" : {
          "modernFormatSavings" : 36486
        }
      },
      {
        "hash" : "6472d1bb4e048587b0f226f300c4732ac88beaa441483c851ef613ac88a0956a",
        "optimizeResults" : {
          "modernFormatSavings" : 568652
        }
      },
      {
        "hash" : "01464e650b8d2798c476a8378af630660b1d4f91bfff89190ab6d0ffa29f139c",
        "optimizeResults" : {
          "modernFormatSavings" : 16141
        }
      },
      {
        "hash" : "285b907a0b6f5a519108724f657e825cc5c093ae05c85f8d7f2d6d483063c359",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "01b61aee04ba84bb1f4655c4fe64c758a5b66b346578980af2024e74b7df7fe3",
        "optimizeResults" : {
          "modernFormatSavings" : 31469
        }
      },
      {
        "hash" : "713810184214227104101651421741287958921211238181772372365913712210101992811489",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2cf22e3870295dd5c4d261d4d6b01bcf460b8c23e5fe95153c2d8546ea857c3b",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "213889839825925133295422126419779662212361691812149461325095142831352549041",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "173227022011523220915311923310811976139572271911017502311411981151541954222124824124",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2a76379fee0cdf97bf4dd811cdf98b10555e791c383d077d89c1500eeb2b5e2c",
        "optimizeResults" : {
          "modernFormatSavings" : 197076
        }
      },
      {
        "hash" : "8166122136921907018745814619440967022414062551252061381929510714521572203188105123",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "92e01a80eb2b0fee4679e5e4433348e2ff390714075d00f501c330622bba300b",
        "optimizeResults" : {
          "modernFormatSavings" : 175066
        }
      },
      {
        "hash" : "14477247670521419884669222018616615521310719919510220216311152154922351081548213295",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "db1fff537b3044e3d8958ae1271bcf15c30a8bee1a0d616c78567bf9d69d16ea",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "727c5610c823dd85b2321f7c55edd565c8c8651f64527ccd5958df0038d753ba",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "636f0fb12604ad079d903efe8ca8dbaec13cd18770edc51333ecdf1b3ddb4ce8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "802515173135187184201211802512424344179254211171857210177709594148743665214121220",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "924926af2a5d2c733dfc03f14aa9d5bd4feaa7bf844186730184e23ee23ff04b",
        "optimizeResults" : {
          "modernFormatSavings" : 58398
        }
      },
      {
        "hash" : "feeb3b0e44fad6a2b6ca36f4b1354d6f6d992dbc3bfd629c5f1c0b253badf690",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "aa70c38e5945f2944250607afc4af686b4f7d2e7159f73b8f147f2d93c4714c4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "4fd8cfe92394bee5a7bf5e13f7fc0c713bc0bc8fea1685f0fc26c03583b5b113",
        "optimizeResults" : {
          "modernFormatSavings" : 55804
        }
      },
      {
        "hash" : "0183093a8608577bb6f7356a72f1f6ceabe659dd7471f201e43b8aa97acb9e6a",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "23391844614218122421710822214731106731722521539103213691461021501325919552190236",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "79b09860376067e6f29bb6db24614f4aad02811a006f0824cbc071500475c7d8",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "18520024616417522192122117572311582451361872161322442411416374210190281432501603381237",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2914c1f9641a653e740d208a02556421f1512d600fa152e446a3021b35ddb685",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "bfaf1a58fbacfece2128cc6a5e6a16849dd62047e6819e7bbbbaef4a0855ffa6",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "321801031832144635132133354813191091013321311562066230232361269512817817251448",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "ebc2cc7e6229bf000e4aa0687c84a19a72f2841986652c105831dafa5c914ce4",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "965d0c5adea998b0d230eb2c2a327b9b5d3cf888b591dd10a077e8ba34c49378",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9a3f4f8c47e9a03e5fc743f4674842e00a170a75a1e9595d298c9986881adc0f",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "66c8fa55565d4bb3820ee275c04a79d56aea25b3cb7eb286e840bbaedfd8a517",
        "optimizeResults" : {
          "modernFormatSavings" : 9442
        }
      },
      {
        "hash" : "8077d018b874ee87b6fd17814476766d2b7b7192fafb63973d518bf27bcf92d4",
        "optimizeResults" : {
          "modernFormatSavings" : 212058
        }
      },
      {
        "hash" : "28a6531d4b5db243e1ab52a9b9c08fd018ab9fb56645df4392a500379a9bbdc3",
        "optimizeResults" : {
          "modernFormatSavings" : 306443
        }
      },
      {
        "hash" : "f0aedd746983b576caf365918c6dac0d808e6e732d0b8178e8674283a86a22c9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1131939920921138182154241498330861301691595202111133137196016843125720644140175225",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "103448214151786811617819117392153762171682073911821418015212227922202453566204162114",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "788e0a0ed4d3643be30f6b6da6fcdcdf29f715e4e8ba61f79b8621d6844cb608",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "9cf435674ce8550ed3d555f1936bf9cdbaa1bbf4cf13fedcfc3f31b5d6f1acbe",
        "optimizeResults" : {
          "modernFormatSavings" : 13929
        }
      },
      {
        "hash" : "209276519775201124314410237245513125453114136129811511782884178895177222815233",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "0f4858aa4f732d95b6d9b4fa45add54ea845e36c198742787da3e423570f920d",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "2292ef3dea252c5b7bd30c1f63e79ed51ff1227b212613f78154c1c3c2a7a71b",
        "optimizeResults" : {
          "modernFormatSavings" : 64183
        }
      },
      {
        "hash" : "2182131839213184136768199120717318717317523264851302055877203173372171521169980128",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5838921774766251916815197168200361111086324558121206228422531802011781553116038225",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "16d5033edb444e59c72e993842b9cc5aad96b763b3ffcdef00b1715435ece2d2",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "1cf600f24a56b962d9a82c8f6c8f36df3871e99bf8b257ce917019ee50039ca7",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "51caba79708cda4908fe7324d0ea9be499fe6b77e6365445ce9975d033645f05",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "5e911c36e3e62a04d5660aa712ac9331e6a956cd6b1d07ec2f1ecc9668ff61e9",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "158951081401073138209150281512071612277192169197552081851282078924712312412413972239130",
        "optimizeResults" : {

        }
      },
      {
        "hash" : "d0149c6c0c2169ba00613acd22a54fb31bc1a34a980ed401e699a21cd0b5288e",
        "optimizeResults" : {

        }
      }
    ],
    "userId" : "auth0|63da7dfab124da2e44bcf1ef"
  }
  """
