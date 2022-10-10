// V2Ray VMess padding identify PoC. Licensed under The JSON License.
// NaLan ZeYu <nalanzeyu@gmail.com>

#include <algorithm>
#include <atomic>
#include <bitset>
#include <map>
#include <thread>
#include <utility>
#include <vector>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cmath>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pcap.h>

// IMPOTANT: changing these values requires rebuilding the lookup table

// if you don‘t want to search all possible seed value range (that is [0, INT32_MAX]), change here
// e.g. V2Ray prior to v4.30.0 uses Unix timestamp (in second) as seed
constexpr uint64_t seed_begin = 0UL; // inclusive
constexpr uint64_t seed_end = 1UL + INT32_MAX; // exclusive

// a larger buffer can decrease the probability of tracking lost and is slower
constexpr size_t ringbuffer_size = 4096;

// your lucky number, recommend > 70, don‘t know why
// each element in this array will generate 24GiB pattern (LOL)
constexpr size_t pattern_pos[] = { 322, 1890 };

// random bytes match threshold
// estimate false positive rate = (1 / (2 ** (padding_match_threshold * 8 / 2))) * 100%
constexpr size_t padding_match_threshold = 12;

// don‘t change values below unless you know what you are doing
constexpr size_t npayload_min = 8;    // inclusive
constexpr size_t npayload_max = 1500; // inclusive
constexpr size_t job_batch = 100000;
constexpr size_t vmess_padding_size_max = 64;
constexpr size_t pattern_pos_max = *std::max_element(std::begin(pattern_pos), std::end(pattern_pos));
constexpr size_t bloom_hashs = 10;
constexpr size_t bloom_size = 14.3 * (seed_end - seed_begin) * std::size(pattern_pos);
constexpr bool use_bloom = false; // not tested yet, don‘t use
constexpr bool search_pattern_strict = false; // search full packet payload instead of search last `vmess_padding_size_max` bytes, veryslow
constexpr bool search_padding_strict = false; // same

static_assert(seed_begin < seed_end);
static_assert(pattern_pos_max + 8 < ringbuffer_size);
static_assert(padding_match_threshold < vmess_padding_size_max);
static_assert(vmess_padding_size_max < npayload_max);

struct tcp_header_t {
    uint16_t src;
    uint16_t dst;
    uint8_t dont_care_1_[8];
    uint8_t len;
    uint8_t flags;
    uint8_t dont_care_2_[6];
};

struct ip4_header_t {
    uint8_t ihl;
    uint8_t dont_care_1_[8];
    uint8_t protocol;
    uint8_t dont_care_2_[2];
    uint32_t src;
    uint32_t dst;
};

struct eth_header_t {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct entry_t {
    uint32_t patternhi;
    uint32_t patternlo;
    uint32_t seed;
    bool operator<(const entry_t &r) const {
        return std::tie(patternhi, patternlo) < std::tie(r.patternhi, r.patternlo);
    }
};

inline namespace gorng {
    // ported from (golang source code)/src/math/rand/rng.go, 
    // not fully tested, don‘t use in anywhere else
    constexpr auto rngLen = 607;
    constexpr auto rngTap = 273;
    constexpr auto rngMask = 9223372036854775807ULL;
    constexpr int64_t rngCooked[] = {
        -4181792142133755926, -4576982950128230565, 1395769623340756751, 5333664234075297259,
        -6347679516498800754, 9033628115061424579, 7143218595135194537, 4812947590706362721,
        7937252194349799378, 5307299880338848416, 8209348851763925077, -7107630437535961764,
        4593015457530856296, 8140875735541888011, -5903942795589686782, -603556388664454774,
        -7496297993371156308, 113108499721038619, 4569519971459345583, -4160538177779461077,
        -6835753265595711384, -6507240692498089696, 6559392774825876886, 7650093201692370310,
        7684323884043752161, -8965504200858744418, -2629915517445760644, 271327514973697897,
        -6433985589514657524, 1065192797246149621, 3344507881999356393, -4763574095074709175,
        7465081662728599889, 1014950805555097187, -4773931307508785033, -5742262670416273165,
        2418672789110888383, 5796562887576294778, 4484266064449540171, 3738982361971787048,
        -4699774852342421385, 10530508058128498, -589538253572429690, -6598062107225984180,
        8660405965245884302, 10162832508971942, -2682657355892958417, 7031802312784620857,
        6240911277345944669, 831864355460801054, -1218937899312622917, 2116287251661052151,
        2202309800992166967, 9161020366945053561, 4069299552407763864, 4936383537992622449,
        457351505131524928, -8881176990926596454, -6375600354038175299, -7155351920868399290,
        4368649989588021065, 887231587095185257, -3659780529968199312, -2407146836602825512,
        5616972787034086048, -751562733459939242, 1686575021641186857, -5177887698780513806,
        -4979215821652996885, -1375154703071198421, 5632136521049761902, -8390088894796940536,
        -193645528485698615, -5979788902190688516, -4907000935050298721, -285522056888777828,
        -2776431630044341707, 1679342092332374735, 6050638460742422078, -2229851317345194226,
        -1582494184340482199, 5881353426285907985, 812786550756860885, 4541845584483343330,
        -6497901820577766722, 4980675660146853729, -4012602956251539747, -329088717864244987,
        -2896929232104691526, 1495812843684243920, -2153620458055647789, 7370257291860230865,
        -2466442761497833547, 4706794511633873654, -1398851569026877145, 8549875090542453214,
        -9189721207376179652, -7894453601103453165, 7297902601803624459, 1011190183918857495,
        -6985347000036920864, 5147159997473910359, -8326859945294252826, 2659470849286379941,
        6097729358393448602, -7491646050550022124, -5117116194870963097, -896216826133240300,
        -745860416168701406, 5803876044675762232, -787954255994554146, -3234519180203704564,
        -4507534739750823898, -1657200065590290694, 505808562678895611, -4153273856159712438,
        -8381261370078904295, 572156825025677802, 1791881013492340891, 3393267094866038768,
        -5444650186382539299, 2352769483186201278, -7930912453007408350, -325464993179687389,
        -3441562999710612272, -6489413242825283295, 5092019688680754699, -227247482082248967,
        4234737173186232084, 5027558287275472836, 4635198586344772304, -536033143587636457,
        5907508150730407386, -8438615781380831356, 972392927514829904, -3801314342046600696,
        -4064951393885491917, -174840358296132583, 2407211146698877100, -1640089820333676239,
        3940796514530962282, -5882197405809569433, 3095313889586102949, -1818050141166537098,
        5832080132947175283, 7890064875145919662, 8184139210799583195, -8073512175445549678,
        -7758774793014564506, -4581724029666783935, 3516491885471466898, -8267083515063118116,
        6657089965014657519, 5220884358887979358, 1796677326474620641, 5340761970648932916,
        1147977171614181568, 5066037465548252321, 2574765911837859848, 1085848279845204775,
        -5873264506986385449, 6116438694366558490, 2107701075971293812, -7420077970933506541,
        2469478054175558874, -1855128755834809824, -5431463669011098282, -9038325065738319171,
        -6966276280341336160, 7217693971077460129, -8314322083775271549, 7196649268545224266,
        -3585711691453906209, -5267827091426810625, 8057528650917418961, -5084103596553648165,
        -2601445448341207749, -7850010900052094367, 6527366231383600011, 3507654575162700890,
        9202058512774729859, 1954818376891585542, -2582991129724600103, 8299563319178235687,
        -5321504681635821435, 7046310742295574065, -2376176645520785576, -7650733936335907755,
        8850422670118399721, 3631909142291992901, 5158881091950831288, -6340413719511654215,
        4763258931815816403, 6280052734341785344, -4979582628649810958, 2043464728020827976,
        -2678071570832690343, 4562580375758598164, 5495451168795427352, -7485059175264624713,
        553004618757816492, 6895160632757959823, -989748114590090637, 7139506338801360852,
        -672480814466784139, 5535668688139305547, 2430933853350256242, -3821430778991574732,
        -1063731997747047009, -3065878205254005442, 7632066283658143750, 6308328381617103346,
        3681878764086140361, 3289686137190109749, 6587997200611086848, 244714774258135476,
        -5143583659437639708, 8090302575944624335, 2945117363431356361, -8359047641006034763,
        3009039260312620700, -793344576772241777, 401084700045993341, -1968749590416080887,
        4707864159563588614, -3583123505891281857, -3240864324164777915, -5908273794572565703,
        -3719524458082857382, -5281400669679581926, 8118566580304798074, 3839261274019871296,
        7062410411742090847, -8481991033874568140, 6027994129690250817, -6725542042704711878,
        -2971981702428546974, -7854441788951256975, 8809096399316380241, 6492004350391900708,
        2462145737463489636, -8818543617934476634, -5070345602623085213, -8961586321599299868,
        -3758656652254704451, -8630661632476012791, 6764129236657751224, -709716318315418359,
        -3403028373052861600, -8838073512170985897, -3999237033416576341, -2920240395515973663,
        -2073249475545404416, 368107899140673753, -6108185202296464250, -6307735683270494757,
        4782583894627718279, 6718292300699989587, 8387085186914375220, 3387513132024756289,
        4654329375432538231, -292704475491394206, -3848998599978456535, 7623042350483453954,
        7725442901813263321, 9186225467561587250, -5132344747257272453, -6865740430362196008,
        2530936820058611833, 1636551876240043639, -3658707362519810009, 1452244145334316253,
        -7161729655835084979, -7943791770359481772, 9108481583171221009, -3200093350120725999,
        5007630032676973346, 2153168792952589781, 6720334534964750538, -3181825545719981703,
        3433922409283786309, 2285479922797300912, 3110614940896576130, -2856812446131932915,
        -3804580617188639299, 7163298419643543757, 4891138053923696990, 580618510277907015,
        1684034065251686769, 4429514767357295841, -8893025458299325803, -8103734041042601133,
        7177515271653460134, 4589042248470800257, -1530083407795771245, 143607045258444228,
        246994305896273627, -8356954712051676521, 6473547110565816071, 3092379936208876896,
        2058427839513754051, -4089587328327907870, 8785882556301281247, -3074039370013608197,
        -637529855400303673, 6137678347805511274, -7152924852417805802, 5708223427705576541,
        -3223714144396531304, 4358391411789012426, 325123008708389849, 6837621693887290924,
        4843721905315627004, -3212720814705499393, -3825019837890901156, 4602025990114250980,
        1044646352569048800, 9106614159853161675, -8394115921626182539, -4304087667751778808,
        2681532557646850893, 3681559472488511871, -3915372517896561773, -2889241648411946534,
        -6564663803938238204, -8060058171802589521, 581945337509520675, 3648778920718647903,
        -4799698790548231394, -7602572252857820065, 220828013409515943, -1072987336855386047,
        4287360518296753003, -4633371852008891965, 5513660857261085186, -2258542936462001533,
        -8744380348503999773, 8746140185685648781, 228500091334420247, 1356187007457302238,
        3019253992034194581, 3152601605678500003, -8793219284148773595, 5559581553696971176,
        4916432985369275664, -8559797105120221417, -5802598197927043732, 2868348622579915573,
        -7224052902810357288, -5894682518218493085, 2587672709781371173, -7706116723325376475,
        3092343956317362483, -5561119517847711700, 972445599196498113, -1558506600978816441,
        1708913533482282562, -2305554874185907314, -6005743014309462908, -6653329009633068701,
        -483583197311151195, 2488075924621352812, -4529369641467339140, -4663743555056261452,
        2997203966153298104, 1282559373026354493, 240113143146674385, 8665713329246516443,
        628141331766346752, -4651421219668005332, -7750560848702540400, 7596648026010355826,
        -3132152619100351065, 7834161864828164065, 7103445518877254909, 4390861237357459201,
        -4780718172614204074, -319889632007444440, 622261699494173647, -3186110786557562560,
        -8718967088789066690, -1948156510637662747, -8212195255998774408, -7028621931231314745,
        2623071828615234808, -4066058308780939700, -5484966924888173764, -6683604512778046238,
        -6756087640505506466, 5256026990536851868, 7841086888628396109, 6640857538655893162,
        -8021284697816458310, -7109857044414059830, -1689021141511844405, -4298087301956291063,
        -4077748265377282003, -998231156719803476, 2719520354384050532, 9132346697815513771,
        4332154495710163773, -2085582442760428892, 6994721091344268833, -2556143461985726874,
        -8567931991128098309, 59934747298466858, -3098398008776739403, -265597256199410390,
        2332206071942466437, -7522315324568406181, 3154897383618636503, -7585605855467168281,
        -6762850759087199275, 197309393502684135, -8579694182469508493, 2543179307861934850,
        4350769010207485119, -4468719947444108136, -7207776534213261296, -1224312577878317200,
        4287946071480840813, 8362686366770308971, 6486469209321732151, -5605644191012979782,
        -1669018511020473564, 4450022655153542367, -7618176296641240059, -3896357471549267421,
        -4596796223304447488, -6531150016257070659, -8982326463137525940, -4125325062227681798,
        -1306489741394045544, -8338554946557245229, 5329160409530630596, 7790979528857726136,
        4955070238059373407, -4304834761432101506, -6215295852904371179, 3007769226071157901,
        -6753025801236972788, 8928702772696731736, 7856187920214445904, -4748497451462800923,
        7900176660600710914, -7082800908938549136, -6797926979589575837, -6737316883512927978,
        4186670094382025798, 1883939007446035042, -414705992779907823, 3734134241178479257,
        4065968871360089196, 6953124200385847784, -7917685222115876751, -7585632937840318161,
        -5567246375906782599, -5256612402221608788, 3106378204088556331, -2894472214076325998,
        4565385105440252958, 1979884289539493806, -6891578849933910383, 3783206694208922581,
        8464961209802336085, 2843963751609577687, 3030678195484896323, -4429654462759003204,
        4459239494808162889, 402587895800087237, 8057891408711167515, 4541888170938985079,
        1042662272908816815, -3666068979732206850, 2647678726283249984, 2144477441549833761,
        -3417019821499388721, -2105601033380872185, 5916597177708541638, -8760774321402454447,
        8833658097025758785, 5970273481425315300, 563813119381731307, -6455022486202078793,
        1598828206250873866, -4016978389451217698, -2988328551145513985, -6071154634840136312,
        8469693267274066490, 125672920241807416, -3912292412830714870, -2559617104544284221,
        -486523741806024092, -4735332261862713930, 5923302823487327109, -9082480245771672572,
        -1808429243461201518, 7990420780896957397, 4317817392807076702, 3625184369705367340,
        -6482649271566653105, -3480272027152017464, -3225473396345736649, -368878695502291645,
        -3981164001421868007, -8522033136963788610, 7609280429197514109, 3020985755112334161,
        -2572049329799262942, 2635195723621160615, 5144520864246028816, -8188285521126945980,
        1567242097116389047, 8172389260191636581, -2885551685425483535, -7060359469858316883,
        -6480181133964513127, -7317004403633452381, 6011544915663598137, 5932255307352610768,
        2241128460406315459, -8327867140638080220, 3094483003111372717, 4583857460292963101,
        9079887171656594975, -384082854924064405, -3460631649611717935, 4225072055348026230,
        -7385151438465742745, 3801620336801580414, -399845416774701952, -7446754431269675473,
        7899055018877642622, 5421679761463003041, 5521102963086275121, -4975092593295409910,
        8735487530905098534, -7462844945281082830, -2080886987197029914, -1000715163927557685,
        -4253840471931071485, -5828896094657903328, 6424174453260338141, 359248545074932887,
        -5949720754023045210, -2426265837057637212, 3030918217665093212, -9077771202237461772,
        -3186796180789149575, 740416251634527158, -2142944401404840226, 6951781370868335478,
        399922722363687927, -8928469722407522623, -1378421100515597285, -8343051178220066766,
        -3030716356046100229, -8811767350470065420, 9026808440365124461, 6440783557497587732,
        4615674634722404292, 539897290441580544, 2096238225866883852, 8751955639408182687,
        -7316147128802486205, 7381039757301768559, 6157238513393239656, -1473377804940618233,
        8629571604380892756, 5280433031239081479, 7101611890139813254, 2479018537985767835,
        7169176924412769570, -1281305539061572506, -7865612307799218120, 2278447439451174845,
        3625338785743880657, 6477479539006708521, 8976185375579272206, -3712000482142939688,
        1326024180520890843, 7537449876596048829, 5464680203499696154, 3189671183162196045,
        6346751753565857109, -8982212049534145501, -6127578587196093755, -245039190118465649,
        -6320577374581628592, 7208698530190629697, 7276901792339343736, -7490986807540332668,
        4133292154170828382, 2918308698224194548, -7703910638917631350, -3929437324238184044,
        -4300543082831323144, -6344160503358350167, 5896236396443472108, -758328221503023383,
        -1894351639983151068, -307900319840287220, -6278469401177312761, -2171292963361310674,
        8382142935188824023, 9103922860780351547, 4152330101494654406,
    };

    struct rngSource {
        int tap;
        int feed;
        uint64_t vec[rngLen];
    };

    int32_t seedrand(int32_t x) {
        constexpr int32_t A = 48271;
        constexpr int32_t Q = 44488;
        constexpr int32_t R = 3399;

        int32_t hi = x / Q;
        int32_t lo = x % Q;
        x = A*lo - R*hi;
        if (x < 0) {
            x += INT32_MAX;
        }
        return x;
    }

    void Seed(rngSource *rng, int64_t seed) {
        rng->tap = 0;
        rng->feed = rngLen - rngTap;

        seed = seed % INT32_MAX;
        if (seed < 0) {
            seed += INT32_MAX;
        }
        if (seed == 0) {
            seed = 89482311;
        }

        uint64_t x = seed;
        for (int i = -20; i < rngLen; i++) {
            x = seedrand(x);
            if (i >= 0) {
                int64_t u = x << 40;
                x = seedrand(x);
                u ^= x << 20;
                x = seedrand(x);
                u ^= x;
                u ^= rngCooked[i];
                rng->vec[i] = u;
            }
        }
    }

    uint64_t Uint64(rngSource *rng) {
        rng->tap--;
        if (rng->tap < 0) {
            (rng->tap) += rngLen;
        }

        rng->feed--;
        if (rng->feed < 0) {
            rng->feed += rngLen;
        }

        auto x = rng->vec[rng->feed] + rng->vec[rng->tap];
        rng->vec[rng->feed] = x;
        return x;
    }

    uint64_t Int63(rngSource *rng) {
        return Uint64(rng) & rngMask;
    }

    void Read(uint8_t dst[], size_t size, rngSource *rng, uint64_t *readPos, uint64_t *readVal) {
        uint64_t pos = *readPos;
        uint64_t val = *readVal;
        for (size_t n = 0; n < size; n++) {
            if (pos == 0) {
                val = Int63(rng);
                pos = 7;
            }
            dst[n] = val;
            val >>= 8;
            pos--;
        }
        *readPos = pos;
        *readVal = val;
    }
}

struct endpoint_state_t {
    gorng::rngSource rng;
    uint64_t readPos;
    uint64_t readVal;
    size_t ringbufferbegin;
    uint8_t ringbuffer[ringbuffer_size]; // always full, no need “ringbufferend“
};

template<size_t N>
static void format_ip4(char (&dst)[N], uint32_t v) {
    snprintf(dst, N, "%u.%u.%u.%u", (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, "%u", v & 0xFF);
}

[[maybe_unused]]
static void print_payload(const u_char *pl, size_t sz) {
    printf("%zu: ", sz);
    for (size_t i = 0; i < sz; i++) {
        printf("%02x", pl[i]);
    }
    printf("\n");
}

static void dont_crash_here_plz_QAQ(void) {
    uint64_t v;
    gorng::rngSource rng;

    gorng::Seed(&rng, 1);
    v = gorng::Int63(&rng);
    assert(v == 5577006791947779410);

    gorng::Seed(&rng, -19);
    v = gorng::Int63(&rng);
    assert(v == 3548795938379065937);
}

static void generate_pattern_worker(entry_t *output, std::atomic_size_t *undonejob) {
    for (;;) {
        size_t firstjob = undonejob->fetch_add(job_batch);
        if (firstjob >= seed_end - seed_begin) {
            return;
        }

        for (size_t job = firstjob; job < firstjob + job_batch; job++) {
            size_t seed = seed_begin + job;
            if (seed >= seed_end) {
                break;
            }
            
            uint8_t randombytes[pattern_pos_max + 8];
            uint64_t readpos = 0, readval = 0;
            gorng::rngSource rng;
            gorng::Seed(&rng, seed);
            gorng::Read(randombytes, sizeof(randombytes), &rng, &readpos, &readval);

            for (size_t j = 0; j < std::size(pattern_pos); j++) {
                // only use randombytes[pattern_pos : pattern_pos + 8] as pattern
                entry_t *p = &output[job * std::size(pattern_pos) + j];
                std::memcpy(&p->patternhi, &randombytes[pattern_pos[j] + 0], sizeof(p->patternhi));
                std::memcpy(&p->patternlo, &randombytes[pattern_pos[j] + 4], sizeof(p->patternhi));
                p->seed = seed;
            }
        }
    }
}

static int generate_pattern(const char *filename) {
    std::vector<entry_t> patterns;
    patterns.resize((seed_end - seed_begin) * std::size(pattern_pos));

    // call worker
    std::atomic_size_t job{ 0 };
    std::vector<std::thread> threads(std::thread::hardware_concurrency());
    for (auto &&t : threads) {
        t = std::thread(generate_pattern_worker, patterns.data(), &job);
    }
    for (auto &&t : threads) {
        t.join(); 
    }

    std::sort(patterns.begin(), patterns.end());

    size_t sz = patterns.size() * sizeof(patterns.back());

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        perror("open");
        abort();
    }

    constexpr const size_t writebatchsize = 8 * 1024 * 1024; // 8 MiB

    for (size_t i = 0; i < sz; i += writebatchsize) {
        ssize_t needwrite = std::min(sz - i, writebatchsize);
        ssize_t actualwrite = write(fd, reinterpret_cast<char *>(patterns.data()) + i, needwrite);
        if (needwrite != actualwrite) {
            fprintf(stderr, "ERR, needwrite != actualwrite\n");
            abort();
        }
    }

    close(fd);

    return 0;
}

static std::pair<entry_t *, entry_t *> open_pattern(const char *filename) {
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open");
        fprintf(stderr, "Note: Did you forget to run './vmess-identify-poc generate' ?\n");
        exit(EXIT_FAILURE);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        abort();
    }

    size_t size = st.st_size;

    if (size % sizeof(entry_t) != 0) {
        fprintf(stderr, "wrong pattern file size\n");
        abort();
    }

    char *map = reinterpret_cast<char *>(mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (map == MAP_FAILED) {
        perror("mmap");
        abort();
    }

    close(fd);

    if (madvise(map, size, MADV_WILLNEED) < 0) {
        perror("madvise");
        abort();
    }

    return { reinterpret_cast<entry_t *>(map), reinterpret_cast<entry_t *>(map + size) };
}

int main(int argc, char *argv[]) {
    dont_crash_here_plz_QAQ();

    if (argc >= 2 && strcmp(argv[1], "generate") == 0) {
        return generate_pattern("patterns.dat");
    }

    auto [patternsbegin, patternsend] = open_pattern("patterns.dat");

    //       ip                 seed      rng internal state
    //       |                  |         |
    std::map<uint32_t, std::map<uint32_t, endpoint_state_t>> ip2state;

    // Longest Common Substring DP array
    auto lcs_ = std::make_unique<std::array<std::array<unsigned int, ringbuffer_size + 1>, npayload_max + 1>>();
    auto &lcs = *lcs_;

    // add all patterns to bloom filter
    std::unique_ptr<std::bitset<bloom_size>> bloom;
    if (use_bloom) {
        bloom = std::make_unique<std::bitset<bloom_size>>();
        for (entry_t *p = patternsbegin; p < patternsend; p++) {
            for (size_t i = 1; i <= bloom_hashs; i++) {
                bloom->set((((static_cast<uint64_t>(p->patternhi) << 32UL) | p->patternlo) * i) % bloom_size);
            }
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("/dev/stdin", errbuf);
    for (;;) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (!packet) {
            break;
        }

        // Ethernet
        size_t ethlen = sizeof(eth_header_t);
        if (ethlen > header.len) {
            continue;
        }
        eth_header_t eth;
        memcpy(&eth, packet, ethlen);
        if (ntohs(eth.type) != 0x0800) {
            continue; // not IPv4
        }

        // IPv4
        if (ethlen + sizeof(ip4_header_t) > header.len) {
            continue;
        }
        ip4_header_t ip4;
        memcpy(&ip4, packet + ethlen, sizeof(ip4_header_t));
        if (ip4.protocol != 0x06 && ip4.protocol != 0x00) {
            continue; // not TCP
        }
        size_t ip4len = (ip4.ihl & 0b1111) * 4;
        ip4.src = be32toh(ip4.src);
        ip4.dst = be32toh(ip4.dst);

        // TCP
        if (ethlen + ip4len + sizeof(tcp_header_t) > header.len) {
            continue;
        }
        tcp_header_t tcp;
        memcpy(&tcp, packet + ethlen + ip4len, sizeof(tcp_header_t));
        if (!(tcp.flags & 0b1000)) {
            continue; // not PSH
        }
        tcp.src = be16toh(tcp.src);
        tcp.dst = be16toh(tcp.dst);

        size_t tcplen = (tcp.len >> 4) * 4;

        // TCP payload
        const u_char *payload = packet + ethlen + ip4len + tcplen;
        size_t npayload = std::distance(payload, packet + header.len);
        if (npayload < npayload_min) {
            continue;
        }
        if (npayload > npayload_max) {
            static bool once = false;
            if (!once) {
                printf("Warning: Packet larger than usual Ethernet.\n");
                printf("Note: If it's not a loopback device, you probably forgot to turn off segmentation offload.\n");
                printf("Note: This message only show once.\n");
                once = true;
            }
            continue;
        }

        size_t searchpatternbegin = search_pattern_strict ? 0 : std::max(0UL, npayload - vmess_padding_size_max);
        for (size_t i = searchpatternbegin; i <= npayload - 8; i++) {
            entry_t val;
            memcpy(&val.patternhi, payload + i + 0, 4);
            memcpy(&val.patternlo, payload + i + 4, 4);

            if (use_bloom) {
                bool pass = true;
                for (size_t i = 1; i <= bloom_hashs; i++) {
                    pass = pass & bloom->test((((static_cast<uint64_t>(val.patternhi) << 32UL) | val.patternlo) * i) % bloom_size);
                }
                if (!pass) {
                    continue;
                }
            }

            auto begin = std::lower_bound(patternsbegin, patternsend, val);
            auto end = std::upper_bound(begin, patternsend, val);
            for (auto p = begin; p != end; ++p) {
                // found pattern `p` in payload, v2ray *may* running on this ip address, and rng used for padding was seeded by `p->seed`
                endpoint_state_t &state = ip2state[ip4.src][p->seed];
                gorng::Seed(&state.rng, p->seed);
                gorng::Read(state.ringbuffer, sizeof(state.ringbuffer), &state.rng, &state.readPos, &state.readVal);
            }
        }

        // if an ip address may running v2ray, update rng state and find longer pattern on payload
        if (ip2state.contains(ip4.src)) {
            for (auto && [seed, state] : ip2state[ip4.src]) {
                size_t longestlen = 0;
                size_t longestend = 0;
                size_t searchpaddingsize   = search_padding_strict ? npayload : std::min(npayload, vmess_padding_size_max);
                size_t searchpaddingoffset = search_padding_strict ?        0 : std::max(0UL, npayload - vmess_padding_size_max);
                for (size_t i = 0; i < searchpaddingsize + 1; i++) {
                    for (size_t j = 0; j < ringbuffer_size + 1; j++) {
                        if (i == 0 || j == 0) {
                            lcs[i][j] = 0;
                        } else if (payload[searchpaddingoffset + i - 1] == state.ringbuffer[(state.ringbufferbegin + j - 1) % sizeof(state.ringbuffer)]) {
                            lcs[i][j] = lcs[i - 1][j - 1] + 1;
                            if (lcs[i][j] >= longestlen) {
                                longestlen = lcs[i][j];
                                longestend = (state.ringbufferbegin + j) % sizeof(state.ringbuffer);
                            }
                        } else {
                            lcs[i][j] = 0;
                        }
                    }
                }

                if (longestlen >= padding_match_threshold) {
                    char srcip[16];
                    char dstip[16];
                    format_ip4(srcip, ip4.src);
                    format_ip4(dstip, ip4.dst);
                    printf("VMess packet found. from %s:%d, to %s:%d, seed %u\n", srcip, tcp.src, dstip, tcp.dst, seed);

                    if (state.ringbufferbegin < longestend) {
                        gorng::Read(state.ringbuffer + state.ringbufferbegin, longestend - state.ringbufferbegin, &state.rng, &state.readPos, &state.readVal);
                    } else {
                        gorng::Read(state.ringbuffer + state.ringbufferbegin, sizeof(state.ringbuffer) - state.ringbufferbegin, &state.rng, &state.readPos, &state.readVal);
                        gorng::Read(state.ringbuffer, longestend, &state.rng, &state.readPos, &state.readVal);
                    }
                    state.ringbufferbegin = longestend;
                }
            }
        }
    }

    return 0;
}
