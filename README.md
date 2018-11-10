# S' Jave na Go: kraš-kurs iz Go-a jednog bivšeg Javašlučara

Evo već mesečak dana pišem isključivo u Go-u, pa reko' da promuhabetim nešto na tu temu. Zato odmah da kažem: ako me išta bude nateralo da se vratim na Javu, smatraću to korakom unazad. Go je kao mladi sportista koji ume da poleti i u sprint kad zatreba, a Java je ćelavi debeljko koji se jedva vuče... mada, mora se priznati, hrabro gura kada se jednom zalaufa. 

Java se izvršava na virtualnoj mašini, pa prvo što treba da uradite da bi se vaš program izvršavao je da instalirate Javašluk. Kontrasta radi, Go se kompajlira u izvršni kod mašine na kojoj ste, pa se vaš program neposredno izvršava. Javini frejmvorkovi, iako strogo gledano nisu deo jezika, nekako su postali njegov nezaobilazni deo, a to usporava programe na startu. Kontrasta radi, Gopheri preziru frejmvorkove: oni žele da im je kôd što bliže Zemlji, golim rukama radeći svoj posao, bez ikakvih frejmvorkovskih rukavica. Dalje, Java je vremenom postala previše apstraktna, i njen kod nije više lako razumeti, što važi i za iskusne programere. Na drugu stranu, Go je mnogo neposredniji i konkretan, a kod je svima lakši za čitanje. I na kraju, Java već duže pokazuje znakove jezičke zastarelosti, dok je Go mlad i dobro osmišljen jezik kojem tek preostaje da se razvija. Minimalizam Go-a u svakom pogledu je razlog što je on eksplodirao u Docker-kontejnerima i primerice Lambda-servisima na AWS-u... munjevito se startuje, i odmah radi svoj pos'o.

Pošto me mrzi da izmišljam brdo usiljenih primera, a ipak želim da ilustrujem jezik, stil, i naročito lakoću paralelnog programiranja u Go-u, diseciraćemo ovde programčić koji mi je nedavno trebao, a koji sam malkice izmenio za potrebe ovog pisanija. Jezičke konstrukcije ćemo komentarisati kako na njih nailazmo, zadržavajući se nešto duže na važnim stvarima. Ovo sve u nadi da će vam se Go dopasti kad završite čitanje. Na poređenja sa Javašlukom (kao i na prednosti Go-a u odnosu na Javašluk) nabasaćete u toku čitanja :smiley:

Treba imati u vidu da sam i ja početnik, te da tehnike opisane ovde možda nisu optimalne. A možda ima i grešaka. Svejedno, meni se Go toliko dopao da sam poželeo da o tome ima nešto više na našem jeziku.

## Token Store

Treba nam nešto što liči na garderobu u pozorištu ili boljem klubu, a što se ovde zove `Store`. Kad god predamo neku glupost na čuvanje, dobijemo žeton, ili *token* koji nam treba da to nešto podignemo. Za opis ovih radnji sklepaćemo sledeći interfejs:

```go
//file: token/token.go
package token
type Store interface {
    Store(payload interface{}) (token string, err error)
    Fetch(token string) (payload interface{}, err error)
}
```
E sad: u ove 4 linije (dobro, ajde, 6, ako ubrojimo komentar i zagradu) ima toliko informacija o jeziku da je teško odlučiti odakle krenuti. Da se ne bi previše zezali, krenimo redom.

### Paketi (packages)
```go
package token
```
U Go-u, kōd se smešta u fajlove koje raspoređujete po direktorijumskom drvetu, da ne kažem baobabu. Zašto baobabu? Pa zato što će se sve što u Go-u napišete naći ispod jednog super-direktorijuma za koji je, verujte mi na reč, najbolje da se zove `~/go/src/github.com`. Osim toga, svaki, pa i najtričaviji pod-direktorijumčić sa tog baobaba Go će smatrati svojom bibliotekom. Imajte u vidu da će se na istom baobabu naći i tuđe biblioteke, što znači da ovo zna da se razgrana do besvesti.

U Go-u, biblioteke se zovu paketi (`package`), tako da ova naredba daje našem paketu ime. Ime mora da se poklapa sa imenom pod-direktorijuma u kojem se paket nalazi. Imena fajlova u istom paketu (dobro, ajde, pod-direktorijumu) nisu bitna, ali treba da se završavaju sa `.go`. Konačni rezultat je ionako unija svih tih fajlova, tako da vam se isto 'vata ako paket napišete kao jedan jedini veliki fajl. Ipak, čitljivije je pakete razbijati u više fajlova, već prema značenju.

---

Primetite upotrebu VELIKIH slova u deklaraciji interfejsa `Store` i njegovih metoda. Ovo nije bezveze. Ako nešto (šta god) u datom paketu počinje velikim slovom, onda je to "nešto" vidljivo i iz drugih paketa. U Javašluku za to služi modifikator `public`, ali je meni ova ekonomičnost Go-a toliko seksi da nemam reči. Kad se samo setim metričke tonaže modifikatora `public` i `private` u Javinim programima, padne mi mrak na oči, dok je u Go-u ovo mrak rešeno. Ako želite da vam u paketu nešto ostane privatno, koristite malo slovo. U suprotnom, koristite veliko. Kraj priče.

Kad smo već kod toga: ja nikad nisam istinski razumeo svrhu Javinog `private` modifikatora. Stvar je u tome što je u Javi nešto *public* ako upotrebite modifikator `public` u deklaraciji tog nečeg, a *private* ako upotrebite - `private`. Ali stvar se ovde ne završava. U Javi, nešto može da bude i `/*package private*/`. Iako za ovo ne postoji službena reč (nego samo komentar; mnogi javašlučari smatraju da za ovo treba da se uvede službena reč), u Javi je nešto `/*package private*/` ukoliko ne upotrebite nijedan od ona dva gorespomenuta modifikatora. U tom slučaju, to "nešto" će biti vidljivo unutar svog paketa, dok za sve druge pakete - neće! 

E sad: razumem to za`public`... razumem i to za `/*package private*/`, jer nam vidljivost unutar istog paketa treba... ali ne razumem koji će nam q `private`? Pa koji to imbecil želi nešto da krije od samog sebe? U Go-u je ovo ispravno rešeno tako što nešto počinje ili velikim ili malim slovom, i ćao zdravo!

### Interfejsi
```go
type Store interface {...}
```
Za gujone, interfejs je obećanje koje ispunjava onaj ko ga implementira (to jest onaj ko implementira sve metode navedene u njemu). Go, za razliku od Jave, nema klase, ali, eto, ima interfejse. Interfejsi su razlog što ni u jednom trenutku nisam doživeo besklasnost Go-a kao falinku. Evo već skoro dve decenije koristim Javu koja ne samo da ima klase, nego bre u Javi ne možete da napišete ni redak korisnog koda van konteksta neke klase. Ipak, poslednjih godina sam često uhvatio sebe da se pitam koji će mi Javine klase? Već duže pišem kōd ravnajući se prema interfejsima, a klase, za koje me najčešće boli ona stvar, uglavnom koristim samo zato što je to u Javi moranje. Nasleđivanje sam odavno prestao da koristim (osim, naravno, ako se ne radi o nasleđivanju interfejsa), a omiljeni štos mi je anonimna implementacija interfejsa. U Javi, ovo je jedini način da izbegnete eksplicitnu deklariciju klase koja vam u stvari ne treba, pa valjda zato.

Naravno, nigde ne treba biti potpuno isključiv: iako postoje alternativne tehnike, i u Javi ponekad valja praviti klasne hijerarhije da ne bi morali da duplirate sopstveni kōd. Ipak, model u kojem se pišu (apstraktne) klasne hijerarhije *predviđene za nasleđivanje* je napušten. Vaše klasne hijerarhije, ako ih ima, treba da ostanu privatne unutar paketa gde su nastale, a svetu eksponirajte interfejse i (najbolje) statične metode koje na ovaj ili onaj način vraćaju tražene instance tih interfejsa. Dati nekome klasnu hijerarhiju za nasleđivanje je nepregledno i potencijalno opasno. A najčešće i nepotrebno, jer korisnik uvek može dobijene instance zamotati u svoje klase, dekorišući ih.

Elem, izgleda da su autori Go-a i ovo ispravno uočili, pa su iz svog jezika najurili klase. Time su interfejsi postali jedna od najvažnijih jezičkih konstrukcija Go-a. Na primer, pored interfejsa izlistanog gore, uočite tip parametra `payload` iz metode `Store`:
```go
    Store(payload interface{}) (token string, err error)
```

Ovaj parametar je tipa `interface{}`. U Go-u, tip `interface{}` označava prazan pra-interfejs koji svaki tip promenljivih u Go-u implementira. Ovo važi za tipove koje sami deklarišete, ali i za tipove koji su deo jezika (*built-in*). One dve vitičaste zagrade jedna odmah iza druge označavaju praznoću interfejsa, to jest da ovaj interfejs nema metode (i u matematici se oznaka `{}` često koristi za prazan skup). Zbog praznoće ovog interfejsa, ispada da je svaka promenljiva tipa `interface{}` *assignment*-kompatibilna sa promenljivom bilo kog drugog tipa. Ovo je prosto zato što je tvrđenje **SVE implementira NIŠTA** jedna valjana formula, zar ne? E sad, pošto smo skapirali ovo, u Go-u je moguće pisati:
```go
    var a int = 5
    var b bool = true
    var f func(int) int = func(x int) int {return x+1}
    var x interface{} = a
    var y interface{} = b
    var z interface{} = f
    fmt.Println(x, y, z)
```

Primetimo da su sve tri promenljive `x`, `y` i `z` istog tipa (`interface{}`), ali da smo prvoj dodelili celobrojnu vrednost, drugoj logičku, a trećoj celobrojnu funkciju koja vraća svoj argument uvećan za 1. "Programčič" će štampati "5", "true" i adresu u memoriji na kojoj počinje funkcija `f`:
```
5 true 0x10959b0
```

---

Ovu dojajnost smo iskoristili u deklaraciji našeg interfejsa `Store`. Parametar i izlazna vrednost `payload` su namerno tipa `interface{}` baš zato što nas se nešto previše ne tiče **šta** nam je predato na čuvanje. U pravoj garderobi, nekad će to biti kaput, nekad jakna, a nekad će neki πčor tamo ostaviti torbicu sa ... ajde da ne ulazimo u to šta ona sve tamo može da ima. Isto tako, ovaj interfejs možete koristiti za proizvodnju i skladištenje kukija u nekoj vašoj Web-aplikaciji, u kojoj će token biti vrednost kukija, a `payload` - status jedne sesije. U svakom slučaju, interfejs `Store` na ovaj način želi da kaže da ga boli uvo za prirodu objekata predatih mu na čuvanje, te da o tome treba da razmišljaju vlasnici.

### Prvi pitonizam: višestruke povratne vrednosti iz funkcija

Eto polako dođosmo i do metoda gorenavedenog interfejsa. Sudeći po potpisu, one trebaju da vrate dve stvari, a ne samo jednu:

```go
    Store(payload interface{}) (token string, err error)
    Fetch(token string) (payload interface{}, err error)
```

Ako me naterate da izdvojim nešto što mi je sve ove godine najviše išlo na onu stvar u Javi, odlučio bih se za to da Javine metode mogu da vrate samo jednu stvar. A ako vam zatreba više stvari, snalazite se kako znate. Ovo se svodi na uvođenje suštinski nepotrebnih Javinih klasa samo zato da bi u njih spakovali tih više stvari. U tu svrhu, već duže koristim `org.apache.commons.lang3.tuple.Pair<L, R>` koji mi, eto, dozvoljava da u povratnu vrednost spakujem dve stvari. A kad mi zatreba treća, dolazi do rađanja mečke :rage:

U Go-u je prirodno da funkcija može da vrati više stvari odjednom; ovo je veoma poznat jezički idiom. U našem slučaju, metoda `Store` vraća token i eventualnu grešku (`nil` ako nema greške), a metoda `Fetch` - payload i grešku. Primetite da smo povratne vrednosti u ovim metodama krstili nekakvim imenima, jer je u Go-u ovo moguće. Iako nije obavezno, ovo zna da bude korisno, a to naročito važi za interfejse čiji pisac već u toku pisanja ima priliku da podari povratnim vrednostima svojih metoda nekakvu semantiku. Ovo će sigurno radovati čitaoce.

---

Sa stanovišta pozivara, ovaj ples izgleda nekako ovako, pod uslovom da u ruci imate nešto što implementira interfejs `Store` (a što se dole zove `store`):

```go
    something := "neki q..."
    token, err := store.Store(something)
    if err != nil {
        // kuknjava zbog greške
    }
    payload, err = store.Fetch(token)
    if err != nil {
        // kuknjava zbog greške
    }
    if payload != something {
        // kuknjava zbog razlike
    }
```
Primetite konstrukciju `token, err := store.Store(something)`, a naročito operator dodeljivanja u njoj (`:=`). On se razlikuje od operatora dodeljivanja koji smo koristili u primeru pre ovog. Go je veoma strog jezik što se tiče tipova, ali kompajler je jedan kul lik koji podstiče programere na lenjost. U Go-u, postoji više načina da deklarišemo promenljivu `something` i dodelimo joj vrednost:
```go
    // vredan programer
    var something string
    something = "bla-bla"
```

```go
    // manje vredan programer
    var something string = "bla-bla"
```

```go
    // lenj programer
    something := "bla-bla"
```

E sad, postoji teorija po kojoj samo lenj programer može biti dobar programer. Ovo je valjda zato što takav sve pokušava da skrati i automatizuje, da se ne bi mnogo zezao, a upravo to spada u prirodu posla kojim se bavi. U poslednjem od ova tri načina, lenji programer traži od kompajlera da samostalno prokljuvi tip promenljive `something` na osnovu izraza na desnoj strani (*type inference*). Zato je ovaj način najprihvaćeniji od strane Gopher-a. Dobićete mnogo WTF-ova ako se bez opravdanog razloga držite samo prva dva.

## Implementacija

Ovo do sada je sve bilo do jaja, ali interfejsi su truba ako ih ništa ne implementira. Pre nego što počnemo da se zezamo sa implementacijom, pogledajmo prvo treba li nam išta od rekvizita, da se oprobamo prvo na nečem manjem. Evo na primer, iz potpisa funkcije `Store` proizilazi da ona obećava da će vratiti `token`. Napišimo najpre (i disecirajmo) jednu kratku funkciju koja generiše slučajan token, da bi izbegli da neki gost falsifikuje tuđi token i mazne tuđi kaput.

##### Najzad malkice pravog koda

Funkcija koja vraća slučajan token izgleda ovako:
```go
import "crypto/rand"
...
const tokenLength = 5
var tokenLetters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func random() (string, error) {
    buf := make([]byte, tokenLength)
    _, err := rand.Read(buf)
    if err != nil {
        return "", err
    }
    for i, v := range buf {
        buf[i] = tokenLetters[v % byte(len(tokenLetters))]
    }
    return string(buf), nil
}
```

Sledi disekcija. Biće malo duže, jer o Go-u malo znamo, ali radimo na tome, zar ne? Krenimo redom:

```go
import "crypto/rand"
```

Ovako se u Go-u importuju paketi. Nakon importa, sve što ima u paketu, a počinje velikim slovom, biće vam dostupno. Ovde smo importovali `crypto/rand` paket zbog toga što kažu da ima toliko zajeban generator slučajnih brojeva da na njemu možete bazirati kriptovalute. Doduše, u Go-u postoji i odrtaveli `math/rand` kojeg treba izbegavati kad god vam treba slučajnost za nekakve šifre ili lozinke (mislim da je on tu samo zbog kompatibilnosti sa starim kodom). Zbog premale entropije, `math/rand` je predvidljiv kao i naši fudbaleri kada šutiraju na gol.

Koliko je Go neposredan u svim pogledima, govori i ovo. Ako želite da baš **ovu** biblioteku koristite u nekom svom programu, dovoljno je pokrenuti komandu `go get`, da bi privukli ovu biblioteku baobabu...

```
    $ go get github.com/gordost/ogou   
```

... a zatim importovati je

```go
    import "github.com/gordost/ogou"
```

Zgodno, zar ne?

---

```go
const tokenLength = 5
```
Da ne žvalavimo previše, ovako se u Go-u definišu konstante. Za standardnu dužinu tokena odabrali smo 5, jer nam treba nešto kratko da nam je golim okom čitljivo, ali ne i prekratko, da bi broj mogućih tokena bio dovoljno veliki. Kod nas je ovaj broj, videćemo, 62 na peti stepen, što je jednako 916 132 832. Znači šanse da neko iz dupeta izvuče važeći token su male.

---

```go
var tokenLetters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
```

Evo najzad jednog pravog pravcatog niza. Dobro, ajde, slajsa, da budemo precizni, ali to je u Go-u skoro isti q.

##### Drugi pitonizam: nizovi i kriške (slices)

Nizovi su važni u svakom jeziku, pa ćemo se ovde malkice zadržati. Prvo recimo da mi ovde želimo da nam tokeni budu golim okom čitljivi, pa smo `tokenLetters` inicijalizovali znakovima koje želimo da vidimo u našim tokenima, izbacivši karakondžule. Ipak, ova linija definiše slajs, a ne niz. Ako želimo pravi niz, njega bismo morali dobiti nekako ovako:

```go
var tokenLetters [62]byte = [62]byte('a','b','c','d','e' ... ,'9') 
```

Ili malkice kraće, jer se tip ovde može izostaviti:

```go
var tokenLetters = [62]byte('a','b','c','d','e' ... ,'9') 
```

Nizovi u Go-u su kao nizovi u svim drugim jezicima. Oni imaju određenu (unapred deklarisanu) dužinu, i sadrže elemente istog tipa. U prethodna dva primera smo deklarisali niz od 62 `byte`-elementa, a onda smo ga napunili `byte`-ovima već u deklaraciji. U primeru pre poslednja dva smo učinili skoro istu stvar, samo što smo tada bili malkice lenji, pa smo samo konvertovali onaj string-literal (ili *bukval*, kako ovo prevesti, jebemliga?) u seriju bajtova, da ne bi morali ručno da ih brojimo i da tako dođemo do broja 62. 

E sad, zbog unapred određene dužine, nizovi u svim jezicima su teški kao slonovi. Zamislite da vam u jednom trenutku zatreba podniz (koji je isto tako, tipski gledano, niz) koji obuhvata sve od 5-tog do 55-tog elementa onog niza gore. Ako bi u jeziku imali isključivo nizove, za taj podniz morali bi alocirati novi niz od 50 elemenata i kopirati potreban sadržaj, da bi tako dobili traženu strukturu. E sad, nagradno pitanje: ne bi li bilo zgodno ako taj novi niz ne bi morali niti alocirati, niti kopirati, nego ga samo nekako prišljamčiti uz onaj stari, da ga yebem kako, ali ako znamo da je sve što nam je potrebno **već** tamo, to bi valjda trebalo biti moguće, zar ne?

Ovde na scenu uskaču kriške (slices). Slajs je prozor kroz koji gledamo niz koji se nalazi u pozadini slajsa. Kroz taj prozor možemo da vidimo ceo niz, a možemo i samo parče (krišku). Stvar je u tome što svaki slajs mora u pozadini imati jedan pravi niz, i taj niz ćemo ovde zvati *niz-pozadinac*. Zbog ove osobine, slajsovi imaju lakašnu strukturu: jedan pokazivač na niz-pozadinca, plus informaciju o lokaciji i veličini prozora. Zbog toga su sve operacije sa slajsovima brze k'o zmija. Na primer, za niz `tokenLetters`, slajs koji se sastoji od 5-tog do 55-tog elementa tog niza, a bez ikakvog tumbanja memorije, dobijamo ovako:

```go
    s := tokenLetters[5:56] // 56-ti nije uključen
```

---

Konstruišimo sada jedan pravi niz, da imamo šta da drndamo po primerima, ali koji neće biti predugačak, zbog ispisa:

```go
    var a = [10]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} 
```

Za slajsove (pa i nizove, koji su sintaktički skoro isto), naročito su važne funkcije `len()` i `cap()`. Prva vraća dužinu slajsa (pardon, niza), a druga - kapacitet. Na primer, odštampajmo nizu `a` njegov `len()` i `cap()`
```go
    fmt.Println(len(a), cap(a)) 
```

```
    10 10
```
Ovo `a` je sada bio pravi niz, a ne slajs. Ponekad to nije lako videti. Stvarno, kako prepoznati razliku? Odmah da kažem da je pitanje na mestu: u Go-u, nizovi i slajsovi se sa stanovišta rada sa njima sasvim malo razlikuju. Ipak, da bi serija nečega bila niz (a ne slajs), potrebno je da joj se u onim uglastim zagradama pri deklaraciji nađe konkretna informacija o tome koliko toga nečega ima, kao što je slučaj sa `[10]int`. Čim tu informaciju izostavite, i upotrebite prazne uglaste zagrade, kao `[]int`, na ovaj ili onaj način dobili ste slajs. Ovo je razlog što je `var tokenLetters = []byte("abc..")` bio slajs.

Izvucimo sada iz niza `a` slajs koji "posmatra" prvih pet članova tog niza, i odštampajmo mu `len()` i `cap()`
```go
    s := a[:5]
    fmt.Println(s, len(s), cap(s)) 
```
```
    [0 1 2 3 4] 5 10
```
Sintaksa je kao u Pitonu. Prazno mesto ispred dvotačke znači od početka, broj 5 iza dvotačke znači do 5-tog elementa isključeno, ili do 4-tog uključeno. Slično, `a[:]` bi bio slajs koji posmatra ceo niz, a `a[5:]` bi bio slajs koji posmatra podniz of 5-tog elementa do kraja niza. Za razliku od Pitona, Go ne trpi negativne brojeve u indeksiranju slajsova, ali dobro.

Na osnovu `cap()`-a (koji je ovde 10), vidimo da je Go ispravno zaključio da je niz-pozadinac ovog slajsa naš očenj poznati niz `a`. Ovo je jasno jer smo baš iz njega izvukli elemente za `s`. To ujedno znači da `s`, iako ima dužinu 5, ima prostor da širi svoj prozor sve do 10. Proverimo ovo jednom malkice perverznom naredbom kojom ćemo od slajsa `s` zatražiti nešto što ovaj na prvi pogled nema:
```go
    s2 := s[3:7]
    fmt.Println(s2, len(s2), cap(s2))
```
```
    [3 4 5 6] 4 7
```
Ispada da je `s` odnekle izvukao nešto što naizgled nema, sudeći prema ispisu gore. Ali ovo upravo znači da je slajs `s` zaista samo prozor kroz koji se posmatra niz-pozadinac `a`, i da je rastegljiv do kapaciteta potonjeg. Potvrdimo ovo tako što ćemo izmeniti nešto u slajsu `s`, pa proveriti da li je ta izmena imala efekat na niz-pozadinca `a`, ali isto tako i na slajs `s2` koji je isto tako baziran na `a`:
```go
    s[3] = 3000
    fmt.Println(a) 
    fmt.Println(s2)
```
```
    [0 1 2 3000 4 5 6 7 8 9]
    [3000 4 5 6]
```
Ispada da jeste. Zapamtite: kad god menjate nešto u slajsu, Go će pokušati da ga smesti niz-pozadincu. A ako zbog nečeg to ne može (uglavnom zbog kapaciteta pozadinca), Go će naći novog mršu za to. Proverimo ovo u dva koraka.

Videli smo da slajs `s` trenutno sadrži `[0 1 2 3000 4]`. Kreirajmo novi slajs `x` dodavši na `s` tačno 5 novih elemenata, i pogledajmo kako je to uticalo na niz-pozadinca:
```go
    x := append(s, 5000, 6000, 7000, 8000, 9000)
    fmt.Println(s) 
    fmt.Println(x) 
    fmt.Println(a)
```
```
    [0 1 2 3000 4]
    [0 1 2 3000 4 5000 6000 7000 8000 9000]
    [0 1 2 3000 4 5000 6000 7000 8000 9000]
```

Slajs `s` je ostao isti kao što je bio, jer operacija `append()` ne mutira `s`. Međutim, niz pozadinac `a` je doživeo niz izmena za potrebe slajsa `x`. Primetimo da smo time `x` napunili do maksimalnog kapaciteta koji njegov niz-pozadinac (i dalje je to `a`) može da izdrži. 
```go
    fmt.Println(len(x), cap(x))
```
```
    10 10
```

A sad, prc: izvucimo novi slajs `y` dodavanjem još jednog elementa na `x`. Očekujemo da Go više neće biti u stanju da ga smesti starom niz-pozadincu, jer ovaj više nema za to potreban kapacitet, i da će biti prinuđen izmisliti novog niz-pozadinca, da bi na njemu temeljio `y`:
```go
    y := append(x, 10000)
    fmt.Println(y) 
    fmt.Println(a) 
```
```
    [0 1 2 3000 4 5000 6000 7000 8000 9000 10000]
    [0 1 2 3000 4 5000 6000 7000 8000 9000]
```


Vidimo da je sada `y` duži od `a`, što znači da `y` sada posmatra nekog drugog niz-pozadinca. Da bi se u to uverili, proverimo da izmenom prvog elementa u `y` nećemo ništa promeniti u `a`, za razliku od ranije:
```go
    y[0] = 333
    fmt.Println(a)
```
```
    [0 1 2 3000 4 5000 6000 7000 8000 9000]
```
___

Da bi zadovoljio `y`, Go je izmislio novog niz-pozadinca za `y`. Primetimo da mi tom novom nizu-pozadincu ne znamo čak ni ime. Pitanje glasi: a gde je sad pa **taj** niz, i kako mu prići? I da li uopšte treba da mu prilazimo? I ako ne, zašto?

Iako i za to postoje tehnike (`package reflect`), mi se na tog novog niza-pozadinca nit' možemo, nit' moramo referisati, osim ako ne pišemo nešto kao debugger. Obične smrtnike treba da boli uvo za nizove-pozadince. U stvari, dugo ćete po standardnim bibliotekama kopati da bi našli mesto gde se neko zeza sa pravim nizom, a ne slajsom. Normalno je kreirati slajs kad god vam zatreba nešto što liči na niz, a nizovima-pozadincima neka se bavi Go.

Primetimo sada nešto malkice čudnjikavo. Ako bi sada najednom odštampali `len(y)` i `cap(y)`, dobili bismo 11 i 20:
```go
    fmt.Println(len(y), cap(y))
```
```
    11 20
```
Au, bre, kako sad pa to? Dobro, 'ajde, razumemo da je `len(y)` sada 11. Na kraju krajeva, `len(y)` smo dobili tako što smo na slajs dužine 10 dodali još jedan element. Ali otkud sad ovo 20? :confused: 

Stvar je u tome što je izmišljanje novog mrše za drndanje jedna skupa operacija koja iziskuje kopiranje starih elemenata, pa Go pokušava da joj spusti cenu. Go razmišlja nekako ovako: *aha, sada mi treba mrša dužine 11, ali šta ako ovaj tenkre malo kasnije doda još nešto, pa mi zatreba 12? Hmmm... 'ajde zato da ja odmah sada, dok sam još tu, sklepam mršu duplog kapaciteta u odnosu na onog starog, jer me to manje košta nego da svaki čas izmišljam novog kad god ova budala doda jedan element*.

Drugim rečima, Go na ovaj način nalazi dovoljan kapacitet za rad vaših slajseva eksponencijalnom brzinom, što je uglavnom zadovoljavajuće.

---

Jebote, toliko reči zbog jednog slajsa. Vreme je da se ide dalje:
```go
    func random() (string, error) {
        ...
    }    
```
Ovo prosto znači da `random()` ne prima nikakve parametre, a vraća string i grešku (error). Po veoma prihvaćenoj konvenciji među Gopherima, ako je error == nil, nema greške. Ovo je i somu jasno. Idemo dalje:

---

```go
    buf := make([]byte, tokenLength)
```
Ovde kreiramo slajs bajtova dužine `tokenLength`, koji će Go inicijalno uvek nafilovati nulama. 

Funkcija `make()` je specijalna funkcija standardne biblioteke koja zna da pravi samo 3 stvari: mape, kanale i slajsove. Ako bacimo pogled na njenu deklaraciju, naletećemo na ovo:
```go
    func make(t Type, size ...IntegerType) Type
```
Ovo znači da prvi parametar ove funkcije prenosi željeni tip za koji moramo biti sigurni da `make()` zna da ga napravi. Kod nas je to slajs bajtova(`[]byte`). Drugi (i eventualno treći) parametar govore o veličini toga što želimo da se napravi. Luk i voda, zar ne?

Neko će sada reći: alo, bre, a zašto sada izmišljamo toplu vodu, a ne koristimo istu konstrukciju kao onda kada smo deklarisali promenljivu `tokenLetters`? I onda smo dobili nekakav slajs, zar ne?

Stvar je u tome što to sada nije baš praktično jer ne znamo unapred čime ćemo ovaj slajs puniti, a onda smo znali (`abcdefg......0123456789`). Sve što znamo je da `buf` želimo puniti nekakvim slučajnim brojevima, a ovo ni u ludilu ne može biti unapred.

---

O nizovima i slajsovima može još mnogo da se priča, ali vreme je da krenemo dalje. Prelazimo na sledeću liniju funkcije `random()`:
```go
    _, err := rand.Read(buf)
```
E ovu liniju valja zaliti, jer je ovo prva linija do sada koja stvarno nešto radi :beer: 

Paket `crypto/rand` nam donosi funkciju `rand.Read()` koja ima sledeći potpis:
```go
    func Read(b []byte) (n int, err error)
```
Potpis nam govori da mi funkciji treba da pošaljemo nekakav slajs bajtova, a `rand.Read()` će da nagura u taj slajs slučajne bajtove od 0 do 255. Osim toga, funkcija nam vraća broj bajtova koje je ugurala u slajs, a i nekakav `error` koji sigurno neće biti `nil` ukoliko je došlo do nekakave greške. S'tim u vezi, zanimljiv je komentar autora funkcije `rand.Read()`, koji kaže: 

*On return, n == len(b) if and only if err == nil.* 

Ovaj komentar za nas ima praktično značenje jer nam crta crno na belo kako da koristimo funkciju. Kako izlazne vrednosti direktno zavise jedna od druge, ovo znači da nam ne trebaju obe, nego samo jedna od njih. Opredelili smo se da to bude `error`, jer nam broj bajtova nije interesantan. Ako do greške dođe, broj bajtova nas se neće ticati jer delimično napunjen bafer ionako ne možemo iskoristiti. A ako do greške ne dođe, tada će broj bajtova, sudeći po komentaru autora, ionako biti jednak dužini bafera, pa nas baš briga. Primetite podvlačilicu sa leve strane naredbe dodeljivanja; njom dajemo signal da smo odlučili da prvu izlaznu vrednost funkcije ignorišemo. A što se tiče druge, nju želimo da je Go sačuva u promenljivoj koju smo krstili `err`.

Postoji još jedan (principijelan) razlog zbog kojeg smo se opredelili da ne ignorišemo grešku: **nikada ne ignorišite greške**! U suprotnom, to će vam se kad-tad obiti o glavu. Zamislite da smo recimo (pogrešno) zaključili da `rand.Read()` nikada neće vratiti grešku, te da smo kod napisali tako što smo ignorisali obe izlazne vrednosti funkcije `rand.Read()`:
```go
    _, _ = rand.Read(buf)    
    for i := 0; i < tokenLength; i++ {
        ...
    }
```
Naš bafer će svejedno biti napunjen... uglavnom, ali ovo je totalno pogrešno. Prvo i prvo, pa valjda onaj ko je pisao `rand.Read()` zna bolje od nas da li ovde može ili ne može da dođe do greške? I ukoliko stvarno ne bi moglo, onda bi potpis njegove funkcije sigurno izgledao drukčije. Zato ako ne ispoštujemo potpis, a do greške jednog dana ipak dođe, program će naizgled nastaviti da radi bez greške, samo što će nam se svi tokeni kod kojih se desila ova greška početi da se završavaju na **a**. U stvari, najveće su šanse da će svi tokeni postati jedno dugačko i tužno **aaaaa**.

---

Sada dolaze na red 3 linije koje su na prvi pogled proste kao pasulj, ali na kojima ćemo se malkice zadržati jer se ovde zaista radi o jako važnim stvarima. Radi se o proveri izlazne vrednosti `err`:
```go
    if err != nil {
        return "", err
    }
```
Kad smo bili šiljokurani, sećam se da su nas učili vrlinama nečega što se onda (a valjda i sada?) zvalo strukturno (ili strukturalno, jebemligaveć) programiranje. Sve nešto kao GOTO naredba je šit, nešto o dobroti grananja `if`-ova i `else`-ova, a naročito to da `return` treba da bude na kraju procedure, tako da se algoritam na izlasku iz svih onih silnih `if`-ova, `else`-ova i petlji prosto ulije u nju. Ovo je valjda imalo veze sa nekakvom dokazivošću korektnosti algoritama, ali u stvari, kad razmislim, učili su nas da pišemo kod koji je bio jednako težak za čitanje kao Krleža. Za ilustraciju koliko ovo može biti zeznuto, naučio sam napamet jednu Krležinu rečenicu sa nekog njegovog gostovanja u studiju na televiziji. Čim su mu dali reč, izvalio je nešto ovako:

> Posmatrajući to pitanje sa stanovišta moralno-političkih kompetencija, moram vam reć da stvar zrači vrlo fluidno, te da nikakva insinuacija endogenih funkcija nije u mom domenu.

Ma idi begaj!

Strukturalni filozofičari bi verovatno bili najzadovoljniji ako bi naš kod izgledao nekako ovako:
```go
func random() (string, error) {
    var ret string
    var err error
    buf := make([]byte, tokenLength)
    _, err = rand.Read(buf)
    if err == nil {
        for i, v := range buf {
            buf[i] = tokenLetters[v % byte(len(tokenLetters))]
        }
        ret = string(buf)
    } else {
        ret = ""
    }
    return ret, err
}
```
Primetite samo jedan `return` i to na kraju, i primetite dužnosno grananje na `if-else`.

Isti filozofičari bi se namrštili na kod koji smo u stvari napisali, jer se `return` usred `if`-a ponaša kao GOTO:
```go
func random() (string, error) {
    buf := make([]byte, tokenLength)
    _, err := rand.Read(buf)
    if err != nil {
        return "", err
    }
    for i, v := range buf {
        buf[i] = tokenLetters[v % byte(len(tokenLetters))]
    }
    return string(buf), nil
}
```

E sad: kako nešto što je 4 linije duže i jedan stepen uvlačenja teksta dublje može da bude bolje, a u stvari je isto? Čak i na ovako malom primeru, prvi listing podseća na onu Krležinu rečenicu gde je on u suštini hteo da kaže... aaaa... ovaj... (kašljuc).... dobro, 'ajde, nije baš da znam šta je time hteo da kaže, ali u tome i jeste poenta.

Zato prihvatite kao jednu od 10 zapovesti da je palamuđenje o `return` naredbi opisano gore mlaćenje prazne slame. Nađite način da iz funkcije izađete što je moguće ranije, čim se za to steknu uslovi, i pobrinite se za to da se uslovi steknu što bliže početku funkcije, a što dalje kraju (na kraju funkcije treba da se izvršava kod kada je sve bilo bez greške). I uvek učinite sve što je u vašoj moći da izbegnete `else`. Jer `else` je zlo, a bogami i naopako. 

###### Još malkice o `else`

Jedna varijanta `if` naredbe u Go-u podstiče na upotrebu `else`. Ovo gore mogli smo napisati i ovako:

```go
    if _, err := rand.Read(buf); err != nil {
        return "", err
    }
```

Primetite da je `if` ovde sastavljen iz dva dela koji su razdvojeni tačka-zarezom. U prvom delu inicijalizujemo promenljive, a u drugom delu, koji mora biti logički izraz, imamo šansu da ih ispitujemo. Istina, baš na ovom mestu to je moglo biti i tako, jer smo odlučili da ignorišemo broj bajtova. Stvar se menja ako bi nam broj bajtova naprasno postao bitan. 

Suština je u tome što su promenljive inicijalizovane na ovaj način vidljive samo u `if` bloku i njegovim `else` granama. Nakon `if-else`, tih promenljivih više nema:
```go
    if n, err := rand.Read(buf); err != nil {
        return "", err
    } else {
        // ovde je n još uvek definisan
    }    
    // ovde n nije definisan
    
```

Uprkos lepoti ove konstrukcije, nemojte koristiti ovu varijantu `if`-a. Ona prosto plače za `else`-om, a `else` valja izbegavati kad god možemo.

---

Ovo što smo do sada rekli o greškama je primenljivo na sve programske jezike, ali, kada se radi o Go-u, uvek preferirajte stil koji se u jednoj rečenici može opisati sa *brigo moja, pređi na drugoga!* E to je upravo ono što smo uradili u ove tri linije koda :smile: Čim dođe do greške, odmah vrući kesten uvaljujemo onome ko nas je zvao, i zadovoljno peremo ruke. 
                                                                         
Međutim, nije sve baš tako prosto: *bar na jednom mestu* u vašem programu morate imati nekakvog sakupljača grešaka koji će sa njima nešto da radi. Jedan od najboljih kandidata za to mesto je `main()` u paketu `main`, a to su funkcija i paket koje morate imati ako želite da se vaš program izvrši (ako nigde nemate `main.main()`, vaš program nije program, nego biblioteka). E sad, šta sakupljač grešaka treba pametno sa njima da radi? Logovanje grešaka u fajl je dobra stvar. Ispis grešaka na ekran je takođe dobra stvar. A ako je greška suviše ozbiljna, nije zgoreg ponekad pozvati i `panic()`. Program će na ovaj način završiti u kanalu pored puta, ali to je ponekad zaista najbolje. 

###### Poređenje sa Javom

U Javi, greška se zove izuzetak (*exception*), a obrada grešaka - obrada izuzetaka (*exception handling*). Go nema obradu izuzetaka kao Java, čime se želi reći da nema ništa nalik *try-catch-finally* - blokovima iz Jave. Ipak, zapitajmo se: koliko su ovi blokovi bolji od onog što Go ima? 

Pogledajmo kako izgleda jedan tipičan *try-catch-finally* blok u Javi, a kako njegov ekvivalent u Go-u. Zamislimo da imamo nekakvu funkciju `open()` koja vraća nekakav resurs koji se na kraju balade treba zatvoriti, ali koja zna i da baci izuzetak ukoliko resurs zbog nečeg ne može da se napravi. U Javi, *try-catch-finally* blok za ovo tipično izgleda ovako: 

```java
    try {
        // Blok u kojem sve ide kao po loju
        r = open();
        r.use();
        return;
    } catch (Exception e) {
        // Blok u kome se obrađuje izuzetak
        System.out.println(e);
        return;
    } finally {
        // Blok koji se uvek izvršiti bez obzira da li je bio izuzetak ili ne
        if (r != null) {
            r.close();
        }
    }
```
E sad, iako je Javina obrada izuzetaka po mnogima do jaja, čak i u ovom maleckom primeru možete nabrojati čak četiri WTF-a:

1. Izuzeci se često obrađuju u blokovima koji su vizuelno daleko od mesta gde su nastali, pa morate stalno da upirete pogled gore-dole
2. Resursi se još češće zatvaraju u bloku koji je vizuelno daleko od mesta gde su nastali, što ume da dovede do zaborava (curenja memorije)
3. `finally` blok je slepac; on nema pojma da li je bilo izuzetka ili ne, pa mora jadan nešto ekstra da proverava
4. Cela konstrukcija deluje Krležijanski komplikovano, ali i nepotrebno dugačko

Ekvivalent ovog bloka u Go-u je daleko ekonomičniji. Go podstiče na to da se greške obrađuju što bliže mestu gde su nastale, a da brigu o zatvaranju resursa skinete sqrca što bliže mestu gde je resurs nastao. Tako je lakše i Go-u i vama, što dovodi do boljeg koda:
```go
    r, err := open()
    if err != nil {
        // Blok u kome se obrađuje greška
        fmt.Println(err)
        return
    }    
    // Ovde je sve kao po loju
    defer r.close()
    r.use()
    return
```
 Primetite upotrebu naredbe `defer`. Ona je kao tempirana bomba koja se aktivira *neposredno pre nego što funkcija efektivno izvrši `return`*. Na ovaj način smo osigurali da će se `r.close()` kad-tad izvršiti, ali ne slepački, kao u Javinom finally-bloku. Jer, ako zbog greške resurs nikada ni ne bude otvoren, `defer` neće ni doći na red jer u tom slučaju neće imati ni šta da se zatvara.
 
Drugim rečima, 1:0 za Go na ovom mestu.

---

Od sada će disekcija funkcije `random()` ići malo brže, jer smo do sada dosta naučili:
```go
    for i, v := range buf {
        buf[i] = tokenLetters[v % byte(len(tokenLetters))]
    }
```

Ovako se u Go-u prolazi kroz niz (ili slajs) u petlji. U njoj će `range buf` vratiti indeks i vrednost svakog pojedinačnog člana niza/slajsa. Ako nam neka od ove dve stvari ne treba, moguće ju je ignorisati korišćenjem podvlačilice (`_`).

U našem slučaju, slajs `buf` sadrži slučajne bajtove na koje ćemo se u petlji referisati preko promenljive `v`, a na njihov indeks preko brojača `i`. Ono što petlja ovde radi je to da ona svaki takav slučajan bajt zamenjuje slučajnim slovom iz slajsa `tokenLetters`. Rezultat je slučajni slajs sastavljen od takvih slova, a to je samo na korak od onog što nam treba. 

---

I evo ga taj korak: sledeća naredba vraća token, kao i `nil` jer nije bilo greške:

```go
    return string(buf), nil
```

Ovde se radi o konverziji jednog tipa u suštinski isti tip. 

Go definiše `string` kao *read-only* slajs sastavljen od bajtova (`[]byte`). Zbog bliskosti ova dva tipa, moguće ih je neposredno "izliti" iz jednog u drugi. Primetimo da smo obrnutu situaciju već imali kada smo inicijalizovali promenljivu `tokenLetters`:
```go
var tokenLetters = []byte("abc...789")
```

---

Uh, raspisasmo se. Krajnji je red je da se vratimo na implementaciju interfejsa `Store`, do ne počnemo zaboravljati ono što smo ovde počeli.


###  Prvi pokušaj, a treći pitonizam: pa ovo mu ga dođe kao rečnik/mapa/yebemliga šta je!

Associjativni nizovi se u Pitonu zovu rečnici, u drugim jezicima mape, tabele i šta sve ne. Asocijativni nizovi su nizovi indeksirani nečim drugim, a ne samo uzastopnim prirodnim brojevima (u kom slučaju se kratko zovu nizovi). Oni postoje u svim programskim jezicima sveta, sa jednom bitnom razlikom. U jezicima poput Pitona i Go-a, asocijativne nizove "priznaje" kompajler, dok u većini drugih jezika kompajler o njima nema pojma, te su tamo asocijativni nizovi implementirani u okiru standardne biblioteke. 

Na ovom mestu nailazimo na još jednu stvar koja mi je godinama išla na tuki u Javi, a to je da interfejs `Map<K, V>` sa svim svojim implementacijama rakolji u biblioteci, pa ga kompajler zarezuje taman toliko koliko i svaku drugu klasu. Zato, kad vam u Javi zatreba neka statična mapa koja se nikad ne menja (što je, verujte, čest slučaj), valja napisati i kod koji je puni. I kao da to nije dovoljno, taj kod mora da se izvrši pre nego što se bilo šta drugo izvrši. Ukratko, na ovom mestu će vam se Java propisno nayebati keve.

Kako Go priznaje mape već na nivou kompajlera, evo načina da deklarišete i inicijalizujete mapu koja ciframa od 0 do 9 daje imena, i to u jednoj jedinoj (doduše iznastavljanoj) liniji koda:
```go
    digitNames := map[int]string{
        0: "nula",
        1: "jedan",
        2: "dva",
        3: "tri",
        4: "četiri",
        5: "pet",
        6: "šes",
        7: "sedam",
        8: "osam",
        9: "devet"}

    // štampa "pet" true
    fmt.Println(digitNames[5])

    // ispravlja grešku u kucanju kod 6
    digitNames[6] = "šest"
```
 
E sad, pošto interfejs `Store` veoma podseća na mapu, iskoristićemo ovu sličnost. Stvar je u tome što je u Go-u moguće "nalepiti" svaki interfejs na bilo koji tip. Iako Go nema klase, u Go-u apsolutno sve što postoji može implementirati bilo koji interfejs.

Ipak, interfejs `Store` ne možemo direktno nalepiti na Go-ovu mapu `map[string]interface{}`. Ovo je zato što mape pripadaju tuđem, a ne našem paketu, a Go zabranjuje lepljenje metoda na tipove koji nisu vaši. Ipak, ovaj problem skoro da ne postoji. Dovoljno je "usvojiti" ono što nam treba u naš paket, te, poput zle maćehe, pastorčetu raditi što nam je volja:

```go
type mapStore map[string]interface{}
```

Ovako se u Go-u poznatom tipu daje novo ime. Primetite da ime novog tipa počinje malim slovom, što znači da će taj tip biti nevidljiv izvan našeg paketa. Kako sad pa to, majku mu? Kako mislimo da potrošači našeg paketa koriste `mapStore`, ako nisu u stanju ni da ga vide?
 
Pa tako što ćemo za potrošače našeg paketa napraviti javni konstruktor koji im vraća instancu interfrejsa `Store`, krijući od njih detalje:

```go
func NewMapStore() Store {
    return mapStore(make(map[string]interface{}))
}
```
Ovde smo prosto napravili instancu mape koristeći funkciju `make()` (koju smo već koristili za slajsove), izlili mapu u naš novi tip i - voilà!

Ipak, kompajler će na ovom mestu početi da kmeči jer mu nije jasno na koju foru `mapStore` implementira interfejs `Store`. Uvalićemo mu cuclu dodavši metode:
```go
func (ms mapStore) Store(payload interface{}) (string, error) {
    token, err := random()
    if err != nil {
        return "", err
    }
    ms[token] = payload
    return token, nil
}

func (ms mapStore) Fetch(token string) (interface{}, error) {
    payload, ok := ms[token]
    if !ok {
        return nil, fmt.Errorf("not found: %v", token)
    }
    return payload, nil
}
```

Kaj se ovde zbilo?

Potpis novododatih funkcija se potpuno poklapa sa potpisom metoda iz interfejsa `Store`. Ali, za razliku od metoda iz interfejsa, ovo više nisu pusta obećanja. Ove dve funkcije imaju telo koje stvarno nešto radi. Osim toga, ove funkcije nisu obične funkcije, kao recimo `random()`. Ove funkcije su *metode* jer uključuju **primaoca** (*receiver*-a), što je ovde promenljiva tipa `mapStore` koju smo krstili `ms`:

```go
func (ms mapStore) Store...
func (ms mapStore) Fetch...
```

Na ovom mestu u deklaraciji Go-ovih funkcija se na poznate tipove lepe interfejsi i obrnuto. Da bi kompajler shvatio tip `mapStore` kao nekakav `Store`, obe metode moraju da budu implementirane. Izbrišite bilo koju od njih, i kompajler će opet početi da kmeči.

Primetite kako se u Go-u radi sa mapama. Budući da je `mapStore` u suštini jedna mapa, kad god želimo nešto ugurati u nju, koristimo pitonijansku sintaksu:

```go
    ms[token] = payload
```
Sintaksa je kao kod nizova, ali ovo je zato što mape možemo shvatiti kao nizove indeksirane nečim drugim, a ne samo uzastopnim prirodnim brojevima.

Kod očitavanja iz mape, sintaksa je malkice drugačija nego u Pitonu: 

```go
    payload, ok := ms[token]
```
Kod očitavanja, Go uvek vraća dve vrednosti. Prva je vrednost koju tražimo, a druga je `bool` koji nam govori o tome da li je vrednost pronađena ili ne. Ovu drugu vrednost potrebno je uvek proveriti, što smo ovde i učinili.

U Javi, kompajler ne poznaje čitanje iz mape, pa to činite pozivima biblioteke:

```java
    v = m.get(key)
```

U slučaju da ključ `key` nije u mapi, `m.get(key)` će vratiti `null`. Međutim, ako ključ `key` jeste u mapi, ali se tamo potrefilo da ima vrednost baš `null`, opet će vam `m.get(key)` vratiti `null`. Drugim rečima, U Javi, ove dve situacije prostim čitanjem nije moguće razlikovati. Zato ako nam treba razlika, u pomoć moramo prizvati metodu `m.containsKey()`, što znači da ćemo u tom slučaju mapu prozivati (skanirati) čitava 2 puta: jednom da bi saznali da li mapa sadrži zadatu vrednost, i još jednom da bi očitali tu vrednost. Ovo je još jedan WTF koji pripisujemo nemoći Jave da vrati više vrednosti odjednom. U Go-u, ovo je elegantno rešeno u jednom koraku.

Na kraju, ovako se konzumira ono što smo do sada napisali:

```go
    store := token.NewMapStore()
    token, err := store.Store("neki q")
    if err != nil {
        panic(err)
    }
    payload, err := store.fetch(token)
    if err != nil {
        panic(err)
    }
    fmt.Println(token, payload)
```

>###### O funkciji `panic()`
>
>Funkcija `panic()` se uglavnom koristi u primerima. U pravim programima, *samo πčke paniče*. Ili opasni frajeri, ali čak i oni retko. Oni u sredini ne paniče, nego dužnosno proveravaju greške i vraćaju ih svom pozivaru. A ako se ipak uspaniče, valja se potruditi i negde napraviti `recover()`. U suprotnom, program će vam odvaliti nosom o ledinu.
>
>Go ima nešto što liči na Javinu obradu izuzetaka, ali ovo se ređe koristi. Mehanizam je baziran na standardnim `panic()` - `defer()` - `recover()` funkcijama. Ukratko, kad pozovete neku funkciju za koju znate da može da paniči, njenu paniku možete smiriti u nekoj od vaših `defer` funkcija koristeći funkciju `recover()`. Na ovaj način programu se daje šansa da se iščupa bez havarije:

```go
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("recovered")
        }
    }
    mayPanic()

    ...

    func mayPanic() {
        panic("panicking...")
    }
```
>
>Ipak, nije lako naći mesto gde se ovaj mehanizam planski i svesno koristi. Jedno takvo mesto je `json` paket, koji ima potrebu za sintaksnom analizom teksta u JSON formatu. Sintaksni analizatoričari su obično puni rekurzivnih poziva koji ponekad znaju otići u velike dubine. E sad, zamislite situaciju kad na dubini od 1000 metara neka od tih rekurzija prokljuvi da tenkre koji je kreirao JSON nije zatvorio desnu zagradu! Ma ko će bre sad da se zeza i da korektno isprogramira da svaki od poziva duž *call stack*-a prekine to što radi, i elegantno izađe? Daleko je lakše dići paniku, a zatim istu smiriti `defer` funkcijom iz sigurnosti čamca na površini.

###### Unit testovi u Go-u

Ekstra je super kad programiranje prema interfejsima podseća na pisanje pozorišnog komada, pri čemu je programer ujedno i pisac i reditelj. Interfejsi su **lica** u komadu, a metode njihove **replike** koje glumci moraju da nauče. Implementacije interfejsa su **glumci**. Nekima ćete biti više, nekima manje zadovoljni, ali je važno, bez obzira na to kojim ste glumcima podelili uloge, da se odvija isti komad. Svi drugi tipovi i funkcije koje nisu ni interfejsi, ni njihove implementacije su **rekviziti**, kao na primer naša funkcija `random()`. Ona podseća na pištolj na stolu koji izađe na videlo čim se podigne zavesa, a za kojeg znate da će kad-tad u toku predstave da opali. 

E sad, šta su unit-testovi? Unit teastovi su **audicija** za glumce; ulogu nećete dati glumcima koji ne prođu audiciju, zar ne? Vrlo je važno da glumce podvrgnete nekakvim izazovima, da bi proverili da li su zaista naučili svoju ulogu, kao i da li je igraju dovoljno dobro. U praksi, kôd nekog programa često menjate i ispravljate, pa vam unit-testovi dođu kao nekakava sigurnosna mreža, proveravajući da li su vaše poslednje izmene nešto syebale.

Za osveženje, a za razliku od Javašluka, Go "priznaje" unit-testove na nivou kompajlera: naredba `go test -v` će izvršiti sve unit testove nađene u direktorijumu (to jest paketu) u kojem ste, i proizvesti nekakav output. E sad, ostaje pitanje: a šta je to što Go smatra unit-testom?

Za Go, unit-testovi su **funkcije** koje se vrzmaju po fajlovima imenovanim po mustri `*_test.go`. Osim toga, imena takvih funkcija moraju početi rečju `Test` (primetite veliko slovo), i te funkcije moraju primati tačno jedan parametar koji mora biti tipa `*testing.T`. Na primer:

```go
import "testing"

func TestSomething(t *testing.T) {...} 
```

Paket `testing` je *built-in* paket koji nam pomaže kod testiranja. Da ne bi mnogo palamudili, napišimo časkom nešto korisno. Lice imamo (`Store`), imamo i glumca(`mapStore`)... napišimo onda kratak unit-test kojim ćemo glumca staviti na muke:
```go
// ./token/mapstore_test.go
package token

import (
    "testing"
)

var mapstore = NewMapStore()

func TestMapStoreFetch(t *testing.T) {
    testStoreFetch(t, mapstore)
}

const samplePayload = "something"
const notAToken = "notAToken"
func testStoreFetch(t *testing.T, store Store) {

    token, err := store.Store(samplePayload)
    if err != nil {
        t.Fatal(err)
    }
    payload, err := store.Fetch(token)
    if err != nil {
        t.Fatal(err)
    }

    if payload != samplePayload {
        t.Fatalf("not same: expected %v, got %v", samplePayload, payload)
    }

    payload, err = store.Fetch(notAToken)
    if err == nil {
        t.Fatalf("error expected, but got none (token: %v, payload %v)", notAToken, payload)
    }
}
```

Ako bismo sada skoknuli do direktorijuma `token` i izvršili ovaj unit-test, dobili bi sledeći output:
```shell
    $ go test -v
    === RUN   TestMapStoreFetch
    --- PASS: TestMapStoreFetch (0.00s)
    PASS
    ok      github.com/aboutgo/token    0.005s
```

Tako izgleda izveštaj kada se sve u redu. Da bi pokazali kako izgleda kad nešto nije u redu, namerno ćemo nešto malkice da pokvarimo, da bi se uverili kako unit-test čumi bagove kao čuma decu. Izbrišimo sve u `mapStore.Store()`, i napravimo izmenu koja uvek vraća isti token, bez sačuvavanja:

```go
func (ms mapStore) Store(payload interface{}) (string, error) {
    
    return "prc!", nil
    
}
```

Ako sada izvršimo test, greška će odmah biti uhvaćena, što znači da je `mapStore` pao na audiciji:

```shell
    $ go test -v
    === RUN   TestMapStoreFetch
    --- FAIL: TestMapStoreFetch (0.00s)
        token_test.go:21: not same: expected something, got <nil>
    FAIL
    exit status 1
    FAIL    github.com/aboutgo/token    0.005s
```

---

Iako `mapStore` na prvi pogled izgleda bezgrešno, budući da smo bili prinuđeni da mu namerno ušpricavamo grešan kod da bi demonstrirali kako unit-testovi otkrivaju bagove, ovo uopšte nije tačno. Sa samo nekoliko linija koda moguće je napisati unit-test koji će ga pocepati k'o svinja mas'an džak:

```go
func TestMapStoreFails(t *testing.T) {
    for i := 0; i < 100; i++ {
        go testStoreFetch(t, store)
    }
    time.Sleep(100 * time.Millisecond)
}
```

Sad kad izvršimo ovaj test, nastaje pičvajz:

```shell
    $ go test -v
    === RUN   TestMapStoreFetch
    --- PASS: TestMapStoreFetch (0.00s)
    === RUN   TestMapStoreFails
    fatal error: concurrent map writes
    fatal error: concurrent map writes
    goroutine 7 [running]:
    runtime.throw(0x1154895, 0x15)
        /usr/local/go/src/runtime/panic.go:608 +0x72 fp=0xc000040640 sp=0xc000040610 pc=0x1029db2
    ...
    ...
    exit status 2
    FAIL    github.com/aboutgo/token    0.030s    
```

Frka je u tome što `mapStore` nije *thread-safe*. Zamislite barmena u nekom baru koji, čim mu neki gost poviče "pivo", a on odmah, kao robot, slepo stavlja novu kriglu na punjenje, ne vodeći pri tom računa da li se tamo već nalazi neka druga krigla koja je već na punjenju. Na podu će neminovno biti mnogo srče i prosutog piva, zar ne?

---

Posmatrajmo naredbu 
```go
    go testStoreFetch(t, store)
```
Primetimo službenu reč `go`, što je naredba po kojoj je Go dobio ime. Ova naredba se izvršava u petlji tačno 100 puta. Svaki put kada se ona izvrši, `Go` lansira novu nit (*thread*) u kojoj se izvršava funkcija `testStoreFetch`. Međutim, odmah zatim, ne čekajući da se prva nit završi, lansira se još jedna ista takva nit, pa još jedna, pa još jedna... i tako 100 puta. Na kraju petlje će biti kao da smo pustili roj od 100 niti od kojih svaka izvršava jednu te istu funkciju pozvanu sa različitim parametirma u nekakvom isprepletanom kompjuterskom vremenu. Na kraju petlje čekamo jednu desetinku sekunde, da nitima iz roja damo dovoljno vremena da naprave karambol i... :boom:

Stvar je u tome što je mapa jedna, a niti/*thread*-ova ima brate 100 komada. I taman kada jedna nit počne u nju nešto da piše, ona biva na pola posla prekinuta jer neka druga nit isto tako pokušava da tamo nešto piše. Ovo dovodi do *fatal error: concurrent map writes*, što izveštaj unit-testa potvrđuje.

U Javi, ovo se lako rešava tako što tamo postoji nešto što se zove `ConcurrentMap`, to jest mapa koja obećava da je *thread-safe*. *Thread-safe* znači da mapa implementira nešto nalik na semafor: samo jedna nit biva puštena da uđe u "kritičnu zonu", dok sve ostale čekaju na crveno dok ona prva ne obavi svoj posao i izađe. E sad: u Go-u, koliko je meni poznato, osim kanala (*channels*), skoro da nema ništa što je samo po sebi *thread-safe*. Međutim, jezičke konstrukcije namenjene paralelnom programiranju u Go-u su toliko razgovetne da se ja lično, što se paralelnog programiranja tiče, mnogo komfornije osećam u Go-u nakon samo mesec dana iskustva nego što sam se ikada osećao u Javi.

###  Drugi pokušaj: `SyncedMapStore`

Nešto od paralelnog programiranja u Go-u smo već videli: to je naredba `go` po kojoj je programski jezik Go dobio ime. Ona lansira novu nit (*thread*) koja izvršava zadatu funkciju (u našem slučaju `testStoreFetch()`). Ovako puštene niti se u Go-u zovu go-rutine (*goroutines*). Go-rutine se ponašaju kao pušteni baloni napunjeni helijumom nad kojima nemamo nikakav uticaj niti kontrolu. Kasnije ćemo videti da je i njih moguće podvrći kontroli, ali o tome kasnije.

Nama trenutno treba način da sinhronizujemo pristup mapi `mapStore`, da se *thread*-ovima ne dozvoli da k'o svinje bezobzirno navale na nju. Za to služi `sync.Mutex` iz Go-ovog paketa `sync`. Ovako deklarišemo promenljivu tipa `sync.Mutex`

```go
    import "sync"

    var mu sync.Mutex
```

Sada je nizbrdo. Na ulasku u zonu koju štitite pozovete `mu.Lock()`, na izlasku - `mu.Unlock()`. Ako neka nit naiđe na `mu.Lock()` u momentu kada je pre nje neka druga nit već prošla muteks, ona će čekati "na crveno" da ta druga nit napravi `mu.Unlock()`. Ako ima mnogo niti, ispred muteksa zna da se ponekad napravi kolona, ali će Go puštati kroz mutex jednu po jednu nit, kao murija kad na autoputu nešto pregradi, pa saobraćaj slije u samo jednu traku, puštajući vozila u koloni jedno po jedno.

Mali je problemčić što naš `mapStore` nema mesta za jedan takav muteks. Doduše... budući da mapa može da primi sve što je kompatibilno sa `interface{}`, ona bi mogla i da proguta i nekakav muteks. Ali problem time ne bi nestao. Da bi se došlo do muteksa sačuvanog u mapi, potrebno je *čitati* iz mape, što je upravo ono što pokušavamo da sinhronizujemo.

U Go-u, za ovaj posao služe strukture. One su mnogo sličnije strukturama u C-u nego klasama u Javi, s' tom razlikom što strukture u Go-u mogu imati metode. Stari kod napisan za potrebe `mapStore` nećemo ni bacati, niti menjati, nego ćemo ga prosto ponovo iskoristiti. Ne zato što je tako jednostavnije (u stvari, nije), nego da bi pokazali jednu od tehnika pomoću koje je moguće postiću efekat nasleđivanja iz jezika koji poznaju klase.

###### Strukture u Go-u

U novom fajlu (`token/syncedMapStore.go`) definisaćemo sledeću strukturu:

```go
type syncedMapStore struct {
    mapstore mapStore
    mu       sync.Mutex
}
```

Naravno, struktura opet počinje malim slovom jer ne želimo da ona bude vidljiva van našeg paketa. Odmah napišimo konstruktor (obična funkcija u Go-u koju zovemo konstruktor; nemojte misliti da Go stvarno ima nešto što se zove konstruktor) koji vraća onaj naš interfejs:

```go
func NewSyncedMapStore() Store {
    return &syncedMapStore{mapstore: mapStore{}}
}
```
Primetimo ampersend (`&`) ispred strukture koju vraćamo. Malo strpljenja, stvar će se razjasniti kad vidimo kako smo implementirali metode. Za sada recimo samo to da taj znak služi da zadovoljimo kompajler.

U stvari, ispada da ga ipak nismo skroz zadovoljili: kompajler i dalje kmeči! Ovo zato što mu nešto nije jasno da `syncedMapStore` implemetira `Store`. Stvarno, kako da vrati nešto što treba da prođe kao `Store`, kad mu fale metode?

Ništa zato, dodajmo metode. Primetite upotrebu naredbe `defer`. Ona osigurava da se mutex neizostavno otključa neposredno pre izlaska:

```go
func (sms *syncedMapStore) Store(payload interface{}) (string, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Store(payload)
}

func (sms *syncedMapStore) Fetch(token string) (interface{}, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Fetch(token)
}
```
Kako je sada kompajler prestao da kuka, prepravimo unit-test od ranije, te provucimo `syncedMapStore` kroz isti:

```go
var syncedmapstore = NewSyncedMapStore()

func TestSyncedMapStore(t *testing.T) {
    for i := 0; i < 100; i++ {
        go testStoreFetch(t, syncedmapstore)
    }
    time.Sleep(100 * time.Millisecond)
}
```
Rezultat je za očekivati:

```shell
    $ go test -v -run "^TestMapStore*|^TestSyncedMapStore*"
    === RUN   TestMapStoreFetch
    --- PASS: TestMapStoreFetch (0.00s)
    === RUN   TestSyncedMapStore
    --- PASS: TestSyncedMapStore (0.10s)
    PASS
    ok      github.com/aboutgo/token    0.108s
```

---

Ostaje da objasnimo šta će nam onaj ampersend u konstruktoru (`&`), a naročito šta će nam one zvezdice kod primaoca (`*`)?

Ovo ima veze sa prenosom parametara u Go-u. Iako se *oni uvek prenose po vrednosti*, Go priznaje vrednosti koje znači pointer na nešto drugo. Na ovaj način se postiže nešto što naliči prenosu po referenci. Primetimo da ovo za parametre važi i za primaoce metoda (*receivers*): u vremenu izvršenja, primaoci nisu ništa drugo nego prvi parametar svojih metoda. U ovom slučaju, na primer, metoda `func (sms *syncedMapStore) Store(payload interface{})` se u vremenu izvršenja transformiše u običnu funkciju čiji je prvi parametar pointer na `syncedMapStore`:

```go
    func Store(sms *syncedMapStore, payload interface{})
```

Znak `*` u potpisu znači da metodi `Store` želimo isporučiti pointer na `syncedMapStore`, a ne goli `syncedMapStore` (što bi bilo prenošenje po vrednosti). Ostaje da se odgovori zašto. Pre toga, primetimo da se promenljive tipa "pointer na nešto" deklarišu kao u C-u, pomoću `*`. Na isti način, znak `&` se koristi da se izvuče pointer na nešto što se nalazi u nekoj promenljivoj, isto kao u C-u.

E sad: šta će nam ovde pointeri?

Mi smo mogli, da smo hteli, napraviti ne-pointersku verziju `syncedMapStore`-a, ali to ne bi rešilo naš problem:
```go
func NewSyncedMapStore() Store {
    return syncedMapStore{mapstore: mapStore{}}
}

func (sms syncedMapStore) Store(payload interface{}) (string, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Store(payload)
}

func (sms syncedMapStore) Fetch(token string) (interface{}, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Fetch(token)
}
```
```shell
    $ go test -v
    === RUN   TestMapStoreFetch
    --- PASS: TestMapStoreFetch (0.00s)
    === RUN   TestMapStoreFails
    fatal error: concurrent map writes
    ...
```

Kad god Go prenosi neki parametar u funkciju, on to čini po vrednosti. To znači da će Go uvek napraviti kopiju vrednosti koju prenosi, nema veze što se ovde radi u strukturi. Zato ako ne želite kopiju, postarajte se da prenesete pointer. I pointer će u krajnjoj konsekvenci biti prenet po vrednosti, ali će bar pokazivati na jednu te istu stvar kao i original, zar ne?

Podsetimo se, naša struktura izgleda ovako:
```go
type syncedMapStore struct {
    mapstore mapStore
    mu       sync.Mutex
}
```

Ovo znači da će svaka kopija te strukture koju Go napravi, osim kopije mape, sadržati i kopiju muteksa `mu`. Međutim, mape u Go-u, poput slajsova i kanala, su na neki način **već pointeri**: svaka kopija neke mape pokazuje na isti segment u memoriji u kojoj original čuva svoje podatke. E sad, to što važi za mape (slajsove i kanale), ne važi za mutekse. To znači da će svaka kopija strukture `syncedMapStore` sadržati različiti muteks. Go-rutine će zato zaključavati i otključavati svoje privatne kopije muteksa bez problema, ali će i dalje nastaviti da se kolju oko iste mape. Otuda bagčina.

Stvar možemo popraviti a da pri tome ipak zadržimo ne-pointersku pririodu najnovije verzije `syncedMapStore`. Ipak, *na nekom mestu* moramo u priču uključiti pointere, jer je potreba nasušna da čak i kopije strukture `syncedMapStore` sadrže suštinski isti muteks. Ovog puta deklarisaćemo sam muteks kao pointer, inicijalizijući ga u konstruktoru:

```go
package token

import "sync"

func NewSyncedMapStore() Store {
    mu := sync.Mutex{}
    return syncedMapStore{mapstore: mapStore{}, mu: &mu}
}

type syncedMapStore struct {
    mapstore mapStore
    mu       *sync.Mutex
}

func (sms syncedMapStore) Store(payload interface{}) (string, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Store(payload)
}

func (sms syncedMapStore) Fetch(token string) (interface{}, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Fetch(token)
}
```

Ovog puta onaj naš unit-test će da prođe. Primetimo da će i u ovom slučaju dolaziti do kopiranja `syncedMapStore`-a kad god pozovemo neku od njenih metoda, ali će te kopije sadržati dva pointera koji pokazuju na istu stvar kao i originali. Zato je pointerka implementacija cele stvari možda ipak čistija. Ako ništa, kopiranje košta nešto, a brže je kopirati jedan pointer nego dva, zar ne? 

###### Zašto Go kopira svako đubre, te moramo da se zezamo sa pointerima da bi ga u tome ponekad sprečili?

Go je izmišljen sa idejom da olakša paraleleno programiranje u kome su tradicinalno jedan od najvećih problema **mutirajući objekti**. Situacije u kojime više niti (*thread*-ova) može da vidi isti objekat i da ga mutira, one su jedan od najvećih izvora bagova koji postoji. Uporedite objekte tipa `String` u Javi sa objektima koje sami napravite. Svaki Javin `String` je nemutirajući objekat (*immutable object*), dok sve što sami napravite, ako se ekstra ne potrudite, nije. Ovo znači da su Javini stringovi neproblematični čak i onda kada više niti (*thread*-ova) može istovremeno da ih vidi, jer im nijedan od njih ne može ništa k'o što ni žaba ne može ništa lešniku: `String` se nakon nastanka više ne može promeniti. Sve što se može je da se na osnovu starih stringova dobijaju novi, ali isto tako nemutirajući stringovi. 

Stvar se drastično menja ako je objekat mutirajući. Da ne bi sejali bagčine koji su veoma zajebani za otkrivanje svuda naokolo, mutacije ili valja sinhronizovati, ili takve objekte treba pisati da budu nemutirajući, poput stringova. Ovo je naročito važno kada šaljemo takve objekte funkcijama kao parametre: da li funkcija mutira objekat ili ne, večito je pitanje? Ako propustimo da adresiramo ove probleme na pravilan način, nayebali smo k'o žuti.  

Međutim, pisanje nemutirajućih objekata u Javi ume da bude zeznuto, zbog čega ljudi izmišljaju čitave biblioteke samo zato da bi sebi olakšali taj posao. Jednu od najkorišćenijih možete naći ovde: [ovde](https://immutables.github.io).

Autori Go-a su želeli da ovaj problem što više saseku u korenu, tako da se objekti u mnogim situacijama standardno ponašaju kao nemutirajući: kad god pošaljete neku strukturu nekoj funkciji kao parametar, funkcija će primiti kopiju te strukture, a ne original. Na ovaj način, funkcija može toj kopiji da radi šta joj je volja, ona time nikada neće biti u stanju da iznenadi pozivara. Čak i kada se to dešava u više niti (*thread*-ova), svaka nit će da se zeza sa svojom kopijom te strukture, što nikad nije frka. Ako ovo nije ono što želite, koristitite pointere, ali time ste odgovornost za sinhronizaciju preuzeli na svoja pleća. 

###### Fino brušenje

Iako je `syncedMapStore` sada na prvi pogled do jaja, ovde se postavlja jedno klasično programersko pitanje: koliko je zaključavanje muteksa implementirano gore **u stvari** efikasno?

Stvar je u tome što će različite niti (*thread*-ovi) zvati `Fetch()` i `Store()` u poretku koji je za nas nepoznat. Zamislite sada da imate 1000 istovremenih poziva metode `Fetch()`, a nijedan `Store()`. Prema algoritmu gore, svih ovih 1000 poziva će se nagurati u red ispred muteksa, sprečavajući jedan drugog da se dešavaju istovremeno. Međutim, budući da `Fetch()` uopšte ne mutira mapu, činjenica je da ništa ne bi smetalo ni da se ovi pozivi *ipak* dešavaju isotovremeno. Mape u Go-u, kao i mnogo čega drugog, ionako su *thread-safe* bar kada se radi o čitanju. Zato jedino što stoji na putu ovom potencijalnom paralelizmu jeste bahatost našeg algoritma gore, i ništa više.

Stvar se drastično menja kada se u priču uključi `Store()`: ova metoda mutira mapu, i to je ono što uopšte generiše potrebu za zaključavanjem muteksa. Bez nje, muteks ne bi ni morali zaključavati. `Fetch()`-ovi su kao ovce, a `Store()`je vuk: ništa ne smeta pustiti 1000 ovaca da istovremeno uđu u tor. Ali čim naiđe vuk, njega valja pustiti samo ako u toru nema nijedne ovce, da ne bi neku od njih pojeo. Isto tako, ne valja u tor istovremeno pustiti ni dva vuka, da se ne bi međusobno poklali. E sad: kako izvesti da `Fetch()`-ovi jedan drugom ne smetaju, ali da, čim naiđe `Store()`, da se naš muteks ipak zaključa?

Za ovo u Go-u služi jedna varijanta muteksa koja se zove `sync.RWMutex`. Ovaj muteks se ponaša kao i poznati `sync.Mutex` gore, sa jednom bitnom razlikom: on ima metode `RLock()` i `RUnlock()`, a to su metode koje **ne sprečavaju** druge čitaoce (t.j. pozivare istih ovih metoda) da istovremeno prolaze muteks. Međutim, `RLock()` ipak sprečava pisce. Što se pisaca tiče, oni će ionako koristiti stare metode `Lock()` i `Unlock()`, sprečavajući sve živo da prođe muteks, osim sebe samih. 

Sad kad ovo znamo, prostakluk je poboljšati algoritam tako da bude daleko efikasniji na čitanju:

```go
func NewSyncedMapStore() Store {
    mu := sync.RWMutex{}
    return syncedMapStore{mapstore: mapStore{}, mu: &mu}
}

type syncedMapStore struct {
    mapstore mapStore
    mu       *sync.RWMutex
}

func (sms syncedMapStore) Store(payload interface{}) (string, error) {
    sms.mu.Lock()
    defer sms.mu.Unlock()
    return sms.mapstore.Store(payload)
}

func (sms syncedMapStore) Fetch(token string) (interface{}, error) {
    sms.mu.RLock()
    defer sms.mu.RUnlock()
    return sms.mapstore.Fetch(token)
}
```

Novi algoritam je efikasniji upravo zato što uključuje samo moranje, dok su sva nemoranja mudro izbegnuta.

###  Kanali (*channels*) i komunikacija između go-rutina

Videli smo kako je lako pokrenuti novu nit (ili go-rutinu) u Go-u. Sve što treba imati od rekvizita jeste neka funkcija koju će ta nit da izvršava. Onda na tu funkciju jednostavno primenimo naredbu `go`, i to je to. 

Za igru, napisaćemo funkciju koja sabira prirodne brojeve između dva zadata prirodna broja, `m` i `n`, i vraća rezultat:
```go
func sum(m, n int) int {
    s := 0
    for i := m; i <=n; i++ {
        s += i
    }
    return s
}
```

Recimo da želimo ovom funkcijom sabrati prve 3 milijarde prirodnih brojeva. Kôd za to izgleda nekako ovako:
```go
    start := time.Now()
    s := sum(1, 3*1000*1000*1000) 
    elapsed := time.Since(start)
    fmt.Println(s, elapsed)
    
```
Na mom kompjuteru ovaj kod će da odštampa sledeći rezultat:
```
    4500000001500000000 874.254312ms
```
Vreme ispod jedne sekunde uopšte nije loše za sabiranje tolike količine brojeva, ali recimo da nam je i to presporo, i da želimo da to skratimo. Ako bi podelili posao na 3 poziva funkcije `sum` tako da svaki poziv sabira svoj blok od milijardu brojeva, učinili bismo samo gore ukoliko bi se to dešavalu u istoj niti/*thread*-u:
```go
    start := time.Now()
    s := sum(0*1000*1000*1000 + 1, 1*1000*1000*1000) 
    s += sum(1*1000*1000*1000 + 1, 2*1000*1000*1000) 
    s += sum(2*1000*1000*1000 + 1, 3*1000*1000*1000) 
    elapsed := time.Since(start)
    fmt.Println(s, elapsed)
```
```
    4500000001500000000 912.923119ms
```

Ipak, na pravom smo putu. Najbolje je da ova tri poziva pokrenemo kao 3 paralelne go-rutine koje bi se izvršavale istovremeno. Ukupno vreme rada će ostati isto, ali, zbog paralelizma, vreme čekanja na rezultat biće svedeno otprilike na trećinu. Trojica radnika iskopaju kanal za trećinu vremena nego što bi to uradio jedan radnik, zar ne?

Međutim, naša funkcija `sum()`, takva kakva je, potpuno je nepogodna za tako nešto. Ona vraća rezultat kao izlaznu vrednost, i tu vrednost je sposobna da vrati samo pozivaru iz iste niti u kojoj je i ona sama. Mi i dalje možemo postići da se pozivi `sum()`-a izvršavaju u paralelnim nitima, ali ti pozivi bi se ponašali kao tri balona napunjena helijumom. Jednom pušteni, oni ne bi imali nikakvu komunikaciju sa zemljom, niti bi ih mi mogli na ikoji način kontrolisati.

Probajmo zato nešto skroz blesavo. Go dopušta bezimene (unutrašnje) funkcije koje možete izvući "kano ljute guje iz njedara" (*closures*), a koje imaju direktan pristup lokalnim promenljivima deklarisanim u glavnoj niti. Ako bi lansirali jednu takvu funkciju u 3 različite niti, interesantno je pitanje kakav će biti rezultat:

```go
    start := time.Now()
    s := 0
    doneCounter := 0
    suma := func(m, n int) {
        for i := m; i <=n; i++ {
            s += i
        }
        doneCounter = doneCounter + 1
    }
    go suma(0*1000*1000*1000 + 1, 1*1000*1000*1000)
    go suma(1*1000*1000*1000 + 1, 2*1000*1000*1000)
    go suma(2*1000*1000*1000 + 1, 3*1000*1000*1000)
    for doneCounter < 2 {
        time.Sleep(1 * time.Nanosecond)
    }
    elapsed := time.Since(start)
    fmt.Println(s, elapsed)
```
Anonimna funkcija koju držimo u promenljivoj `suma` dodaje brojeve onako kako nailaze direktno na `s`, a ova promenljiva je definisana u glavnoj niti. Osim toga, funkcija inkrementira `doneCounter` čim završi veliko sabiranje. Glavna nit čeka da sve tri go-rutine završe posao u petlji, dremajući ako mora, ali stalno proveravajući da li je promenljiva `doneCounter` dostigla očekivanu vrednost. A kad je bude dostigla, glavna nit štampa rezultat. 

Ipak, rezultat koda gore je katastrofa:

```
    1557301230835831450 2.169120056s
```

Iako se ništa nije zaglavilo (u Go-u je sabiranje celobrojnih vrednosti očigledno atomska operacija koja se ne može se usred posla prekinuti), ovaj rezultat, kao prvo, uopšte nije tačan. Stvarno, kako to da smo na promenljivu `s` očigledno dodali svih 3 milijarde potrebnih brojeva, a ipak dobili netačan rezultat?

Stvar je u tome što se naredba `s += i` koju izvršava funkcija `suma` sastoji od bar dve različite operacije: 1. `očitavanje starog s-a` 2. `upis novog (inkrementiranog) s-a`. Svaka od tih operacija jeste atomska, ali one zajedno u nizu to nisu: u prostoru *između njih* postoji opasnost da se ušunja neka druga nit/*thread* i da zajebe stvar. Svaki put kada se to desi (a u ovom slučaju desiće se mnogo puta, zato što je veliki broj sabiranja sabijen u jednu tačku prostora i vremena), sabiranje prosto "prezupči". Na primer, zamislite da nit A očita promenljivu `s` koju nit B samo što nije promenila. Za vreme dok nit A računa izraz `s + i`, nit B je već promenila `s`, tako da, kad nit A kasnije upiše svoje novoizračunato, ali sada već zastarelo `s`, ona će poništiti doprinos niti B. Na ovaj način, mnogi od sabiraka bivaju progutani, što je razlog da nam konačna suma nije tačna.

Osim toga, u kodu gore ima jedan veeeeeliki bag. Sve što smo rekli za `s` važi i za `doneCounter`, tako da smo prosto imali sreće da `doneCounter` nije prezupčio na isti način kao `s`. Da se to desilo, uzaludno bi čekali da se ove 3 go-rutine završe. U stvari, one bi se jadne još i završile, samo mi to ne bismo znali. Zato nikada ne inkrementirajte brojeve na ovaj način. Koristite `doneCounter++`, što je u Go-u atomska operacija.

Novo vreme izvršavanja koje smo dobili gore je isto tako katastrofa. Ovo je zato što sada niti (*thread*-ovi) čekaju čak na dva interna semafora kod atomskih operacija 1. i 2, što znači da se niti provlače kroz ovaj kōd k'o pilići kroz vrzinu. 

Korektnost rezultata možemo popraviti tako što ćemo "atomizirati" operacije 1. i 2, ali nemojte ni pokušati ovo izvršiti, toliko će biti sporo:
```go
    mu.Lock()
    s += i
    mu.Unlock()
```

---

U pomoć nam priskaču kanali (`chan`). Kanal u Go-u je kao nekakav voki-toki kojim možemo da snabdemo go-rutine pre poletanja, a pomoću kojeg nam one javljaju šta se kod njih dešava (disekcija sledi):
```go
    start := time.Now()
    suma := func(m, n int, c chan int) {
        su := 0
        for i := m; i <=n; i++ {
            su += i
        }
        c <- su
    }
    ch := make(chan int, 3)
    go suma(0*1000*1000*1000 + 1, 1*1000*1000*1000, ch)
    go suma(1*1000*1000*1000 + 1, 2*1000*1000*1000, ch)
    go suma(2*1000*1000*1000 + 1, 3*1000*1000*1000, ch)
    s := <-ch
    s += <-ch
    s += <-ch
    elapsed := time.Since(start)
    fmt.Println(s, elapsed)
```
Rezultat, osim što na njega čekamo mnogo kraće, je uz to i tačan. Istina, vreme izvršavanja nije svedeno baš na trećinu kao što smo obećali, ali tu je negde. 

```
    4500000001500000000 310.63173ms
```

Kako smo ovo postigli?

Prvo smo napravili kanal u koji mogu da se guraju celobrojne vrednosti, a u kojem očekujemo 3 komada takvih vrednosti. Njega smo kreirali od ranije poznatom funkcijom `make()`:
```go
    ch := make(chan int, 3)
```
Anonimnu funkciju `suma` smo snabdeli ekstra-parametrom da bismo joj predali kanal za komunikaciju "sa tornjem". Čim funkcija završi sabiranje, ona jednostavno ugura dobijeni rezultat u kanal:
```go
    c <- su
```
Primetite ovde smer strelice. Strelice uvek pokazuju s' desna na levo. Ako pokazuju prema kanalu, u kanal se nešto gura. Ako je obrnuto, iz kanala se nešto vuče/čita. Nakon što je lansirala 3 go-rutine, glavna nit čita iz kanala tačno 3 puta, dobivši konačan rezultat prostim sabiranjem:
```go
    s := <-ch
    s += <-ch
    s += <-ch
```
I to je to. Jednostavno, čisto, bez gužve. Ovaj idiom je toliko sladak da nije čudo što Go postaje sve popularniji, a neki ga zovu i jezikom budućnosti.

---

Ipak, nemojte nikad ovako čitati iz kanala, osim ako ste sigurni da će vaša go-rutina da završi posao u prihvatljivom roku. Čitanje iz kanala je *blokirajuće*, što znači da će vaš program ovde 3x da stane, i da čeka sve dok se na kanalu ne pojavi neka vrednost. E sad: a šta ako se tamo nikada ne pojavi nikakva vrednost? Ili ako nam je vreme čekanja na tu vrednost neprihvatljivo? Takve slučajeve ćemo doživeti kao da se program zaglavio, zar ne?

Snabdene voki-tokijem ili ne, go-rutine, jednom lansirane, ponašaju se kao pušteni baloni nad kojima u opštem slučaju nemamo kontrolu. Iako je moguće uz nešto grčenja isprogramirati *nekakvu* kontrolu, ipak je najčistije pobrinuti se da se go-rutine kad-tad završe, a za komunikaciju sa njima koristiti kanale. Isto tako, uvek dajte svojim go-rutinama rok u kojima bi trebalo da završe svoj posao. Ovo se u Go-u lako implementira korišćenjem naredbe `select`, jedne prelepe jezičke konstrukcije motivisane upravo potrebama paralelnog programiranja.

#### Naredba `select` 

Da bi ilustrovali poentu, učinićemo našu funkciju `suma` namerno nestašnom, da bi je kasnije ukrotili naredbom `select`. Recimo da funkcija `suma` na početku sa verovatnoćom 0.25 odlučuje da li da spava jednu čitavu sekundu ili ne. Ovako simuliramo nepredvidljivost vremena izvršavanja. U realnom životu, ova nepredvidljivost može nastati zbog nekog upita nekoj preopterećenoj bazi podataka, ili zbog nekog pičvajza na mreži, nebitno:

```go
    suma := func(m, n int, c chan int) {
        if (rand.Intn(4) == 0) {
            time.Sleep(1 * time.Second)
        }
        su := 0
        for i := m; i <=n; i++ {
            su += i
        }
        c <- su
    }
```

Verovatnoća da će bar neka rutina ovde da spava je 55/64, što je dosta veliko da uz samo par pokušaja naletimo na ovu situaciju. Kada se to desi, rezultat izgleda ovako:

```
    4500000001500000000 1.297851977s
```

Rezultat preko jedne sekunde je ovde očekivan, jer je bar jedna go-rutina donela odluku da dremne čitavu sekundu. E sad: zamislite sada da našim go-rutinama želimo dati rok od samo jedne sekunde za čitav posao. A ako ne završe taj posao, želimo da glavni program liže svoje rane smatrajući da nema nikakav rezultat. Za ovaj scenario može poslužiti prelepa konstrukcija `select`, konstrukcija koja je toliko razgovetna baš zato što je misaono rekurzivna. Jer, stvar se opet svodi - na čitanje sa kanala!

Spakovaćemo sakupljanje podrezultata u posebnu funkciju kojoj ćemo dati poseban kanal kroz koji će nam ona vratiti konačan rezultat. Sada se sve dešava u toj novoj funkciji: ona kreira one stare go-rutine za sabiranje, kao i kanal za komunikaciju sa njima:

```go
    wait := func (chRes chan int) {
        ch := make(chan int, 3)
        go summa(0*1000*1000*1000 + 1, 1*1000*1000*1000, ch)
        go summa(1*1000*1000*1000 + 1, 2*1000*1000*1000, ch)
        go summa(2*1000*1000*1000 + 1, 3*1000*1000*1000, ch)
        s := <-ch
        s += <-ch
        s += <-ch
        chRes <- s
    }
```

Sada ćemo kreirati kanal preko kojeg će nam go-rutina `wait` vratiti konačan rezultat, kojeg ćemo zatim sačekati naredbom `select`:

```go
    c := make(chan int, 1)
    go wait(c)
    select {
    case <-time.After(1 *time.Second):
        fmt.Println("no result - timeout expired")
    case s := <- c:
        elapsed := time.Since(start)
        fmt.Println(s, elapsed)
    }
```

Naredba `select` služi za čekanje na jedan ili više zadatih kanala, pa šta prvo naiđe. I ova naredba je blokirajuća. Međutim, šta god da naiđe na nekom od kanala, program će odblokirati, t.j. izaći iz `select`-a i nastaviti sa radom. Ovde nam u pomoć priskače paket `time` koji nudi veoma zgodnu funkciju `After()`, do jaja za tajmere. Ona vraća kanal u koji će sigurno nešto da upiše nakon vremena koje smo mu zadali. Tako ako se nešto pojavi prvo na **tom** kanalu, smatraćemo da se desio neki pičvajz, te da konačan rezultat nemamo. U suprotnom, rezultat je tu, i sve što preostaje učiniti jeste odštampati ga.

---

E sad: u slučaju da se ovde zaista desi tajmout, kakva je sudbina one četiri go-rutine koje smo lansirali?

Sudeći po tome kako smo ih napisali, one će jednom sigurno završiti svoj posao, samo neće imati kome da predaju rezultat: mi tada više nećemo biti tu. Drugim rečima, mi smo na njih u tom slučaju zaboravili. Zato je bitno pisati go-rutine tako da završavaju započeti posao čak i onda kada na njih zaboravimo. Ponekad ih je potrebno malkice cimnuti za rukav, signalizirajući im da prekinu da rade šta god da rade, ali ove tehnike nećemo ovde pokazati; ionako smo se previše raspisali. Zapamtite: ako propustite da **nešto** učinite, nakupiće vam se đubre od nezavršenih go-rutina koje, osim što žderu memoriju, uz to troše i CPU.

___
___
---

Na ovom mestu sam na početku mislio da završim ovo pisanije, ali mi savest nekoga ko ovo radi profesionalno ne da mira. Stvar je u tome što `syncedMapStore` nije ni za q. Dobro, u redu je ponekad skratiti pisanje nekog parčeta softvera ako mu, bar pod nekim uslovima, vidimo upotrebnu vrednost. Stvar je u tome što bi ti uslovi u ovom slučaju bili bulšitoliki, i glasili bi nešto kao *`syncedMapStore` možete koristiti, ali samo pod uslovom da s' vremena na vreme restartujete program*!

A ovo je, naravno :scream:

Problem je u tome što se u pravim garderobama često dešava da neki lik ili likuša preda neko njesra na čuvanje, a onda se na to popišmani i nikada se ne pojavi da to preuzme. Možda zato što je lik zaboravan, ili mu to nije dovoljno vredno. Nebitno, garderoba mora da ima način da uradi nešto sa stvarima koje tamo rakolje nenormalno dugo. U suprotnom, tamo bi se godinama nakupilo toliko đubreta da bi na kraju garderoba postala prenatrpana.

Sa garderoboama je ovo još i kako-tako, ali šta ako se vaš `Store` koristi za čuvanje kukija na nekom serveru, gde ih em možete imati na milione, em im po prirodi posla **morate** davati nekakav rok trajanja? Zato...

###  Treći (i poslednji) pokušaj: `TokenStore`

Sve u svemu, valja u priču uvesti TTL (*Time To Live*), ali kako? 

Na prvi pogled, to ne izgleda naročito teško, ali ovo je ipak nešto zeznutije nego što to na prvi pogled izgleda. Podsetimo se prvo šta trenutno imamo od svijetlog oružja:

```go
type syncedMapStore struct {
    mapstore mapStore
    mu       *sync.RWMutex
}
```

Bogami, baš mršavo. Kao prvo, ovaj muteks nam ovde ništa ne pomaže, jer nam on ne donosi ništa funkcionalno novo. Doduše, tu je `mapStore`, a sa tim već može da se barata.

Budući da `mapStore` može da primi svašta nešto, `payload`-ove možemo da pakujemo u koverte na kojima pre toga naškrabamo vreme nastanka i rok trajanja. Svaki put kad klijent pozove `Store`, mi `payload` spakujemo u koverat, a onda **taj koverat** sačuvamo u `mapStore`. Kasnije, kad naiđe `Fetch()`, mi prvo iscimamo mapu da nam preda traženi koverat, pa vratimo rezultat.

Koverat koji smo opisali izgleda ovako:
```go
type envelope struct {
     payload interface{}
     created time.Time
     ttl time.Duration
}
```

Da bi se što manje zezali, na `*envelope` odmah lepimo metodu koja nam vraća da li 
`payload` u njemu još važi ili ne.
 
```go
func (e *envelope) expired() bool {
    return e.created.Add(e.ttl).Before(time.Now())
}
```

---

Ovo sve do sada je bilo manje-više moranje. Recimo da se naša nova implementacija interfejsa `Store` zove `tokenStore`. Ona proširuje postojeću strukturu `syncedMapStore`, ali definiše i TTL koji će se koristiti:
```go
type tokenStore struct {
    syncedMapStore
    ttl time.Duration
}
```

Primetite ugnježdavanje struktura: `syncedMapStore` na ovaj način postaje nerazdvojni deo strukture `tokenStore`, kao zakrpa na vreći. Elementima ugnježdene strukture se pristupa kao da pripadaju glavnoj strukturi (oni u stvari i pripadaju). Ako imamo instancu strukture `tokenStore` koja se zove `ts`, muteksu iz `syncedMapStore` se pristupa kao da direktno pripada strukturi `ts`,:

```go
    ts.mu
```
  
S' tim u vezi, primetimo jednu jako interesantnu stvar. Ako i sada, kao što smo ranije činili, napišemo konstruktor za `tokenStore`, kompajler ovog puta neće kmečati. Zašto?

```go
func NewTokenStore(ttl time.Duration) Store {
    mu := sync.RWMutex{}
    syncedMapStore := syncedMapStore{mapStore{}, &mu}
    return &tokenStore{syncedMapStore, ttl}
}
```

To je zato što `tokenStore` već implementira `Store`! Ovo nije lako odmah videti, ali u Go-u, ako strukturu koja implementira neki interfejs ugnezdite na ovaj način u neku drugu strukturu, onda se toj novoj strukturi priznaje da implementira isti interfejs. Zgodno, zar ne?

Ipak, mi ovde moramo prejahati obe metode, zbog potrebe pakovanja i raspakivanja koverti koju nismo ranije imali:

```go
func (ts *tokenStore) Store(payload interface{}) (string, error) {
    envelope := envelope{payload, time.Now(), ts.ttl}
    return ts.syncedMapStore.Store(&envelope)
}

func (ts *tokenStore) Fetch(token string) (interface{}, error) {
    envelopeProbe, err := ts.syncedMapStore.Fetch(token)
    if err != nil {
        return nil, err
    }
    envelope, ok := envelopeProbe.(envelope)
    if !ok {
        return nil, fmt.Errorf("wrong type fetched")
    }
    if envelope.expired() {
        return envelope.payload, fmt.Errorf("token expired: %v", token)
    }
    return envelope.payload, nil
}
```

U kodu gore nema mnogo toga novog, tako da nećemo potrošiti previše vremena na disekciju. Ipak, uočimo liniju

```go
    return ts.syncedMapStore.Store(&envelope)
```

Ovako se u Go-u poziva metoda ugnježdene strukture (u našem slučaju `syncedMapStore`) bez opasnosti da uđemo u neželjnu rekurziju. Ipak, ovo se ne koristi previše često. Za razumevanje Go-a, važnije je reći nešto o sledećoj liniji: 

```go
    envelope, ok := envelopeProbe.(envelope)
```

Hmmm... ovo je čudno. I liči na nešto poznato, a i ne liči :unamused:

Možda malkice buni to što su identifikator `envelope` koji se nalazi krajnje levo, i identifikator `envelope` krajnje desno - dve različite stvari! Onaj levo je ime promenljive `envelope`, a desno - ime tipa `envelope`, što je naša struktura gore. Za Go, ovde nema zabune; Go poznaje kontekst u kojem se ova dva doslovce jednaka identifikatora koriste, pa zna da ih razlikuje. Ali za ljude kojima je Go nov jezik, ovo može biti problem. Zato prekrstimo ime promenljive u nešto drugo, i pokušajmo pogoditi šta ova konstrukcija radi:

```go
    env, ok := envelopeProbe.(envelope)
```

Sada je valjda malkice jasnije. 

Ova konstrukcija se u Go-u zove *type assertion*, jebemliga kako se prevodi na srpski. Možda *utvrđivanje tipova*?

Elem, `envelopeProbe` je promenljiva koja u ovoj konstrukciji mora da bude instanca nekakvog interfejsa. Ova konstrukcija utvrđuje da li je vrednost te promenljive istog tipa kao onaj naveden u zagradi iza one tačke. Ako nije, `ok` će postati `false` i sa promenljivom `env` nećemo moći ništa pametno uraditi. Ali ako jeste, `ok` će postati `true`, i promenljivu `env` ćemo nadalje moći koristiti kao promenljivu tipa kojeg utvrđujemo.

Pošto znamo kako je nastala promenljiva `envelopeProbe`, tu liniju smo mogli napisati i ovako, ignorišući `ok`:

```go
    env, _ := envelopeProbe.(envelope)
```

Ipak, nemojte ovo raditi, ma koliko da ste sigurni da će `ok` uvek biti `true`. Ova provera sasvim malo košta da bismo je izbegavali čak i kad je očigledno.

Primetimo da, čim je provera prošla, promenljivu `env` možemo koristiti kao promenljivu tipa `envelope`:

```go
    if envelope.expired() {
        return envelope.payload, fmt.Errorf("token expired: %v", token)
    }
```

I to bi bilo to. 

Ovim smo tokenima dali novu funkcionalnost (rok trajanja), ali time se priča ne završava. Rekli smo da izjanđale tokene valja čistiti, jer u suprotnom naša mapa bi samo rasla, ali kako?

---

U Go-u, ako znamo ključ, stavku iz mape sačuvanu pod tim ključem moguće je brisati ovako:

```go
    delete(m, key)
```

E sad, kako ovde da znamo koji ključ da brišemo? 

Imajmo u vidu da su mape skroz nepogodne da po njima jurcamo izjanđale tokene. U mapi, redosled tokena je za nas slučajan. Da bi pronašli jedan jedini matori token, rizikujemo da zbog toga moramo da prođemo celu mapu, a ovo nije uredno sve dok postoji šansa da neke druge niti čekaju na mapu kao na ozeblo sunce.

Kompletnosti radi, u Go-u, prolaz kroz neku mapu se vrši ovako:
```go
    for k, v := range m {
        ...
    }
```
U našem slučaju, ako bi prolazili kroz našu mapu na ovaj način, to bi valjalo činiti iza zaključanog muteksa dok gomila drugih niti (*thread*-ova) moguće čeka na upis ili čitanje. Ovo programer čiste savesti ne može sebi dozvoliti.

Moramo naći način da nam pristup izjanđalim tokenima bude brži. U tu svrhu, prvo ćemo definisati ono što znamo da moramo. Definisaćemo strukturicu u kojoj držimo informaciju o jednom tokenu, kao i informaciju o izjanđalosti istog. Za ovo je dovoljno da na jednom mestu grupišemo token i kovertu koju smo pod tim tokenom sačuvali:

```go
type entry struct {
    token    string
    envelope *envelope
}
```

Kad god nam je u ruci instanca ove strukture, izjanđalost tokena možemo proveriti metodom `expired()` koju implementira `*envelope`. Budući da bi u tom slučaju znali i token, znali bi šta da brišemo iz mape ukoliko je on izjanđao. *So far so good*.

E sad: jedno je imati ovu strukturicu, ali pronalaziti tokene zrele za progon, to je nešto sasvim drugo. Mi želimo da nam se brisanje starih tokena dešava što brže, uz što manje blokiranja drugih niti (*thread*-ova) na nekom muteksu. Zbog toga nam se čini super ako ceo taj posao završi sama metoda `Store()`. Ona ionako **mora** u jednom trenutku zaključati muteks, kako god se dovijali. Zašto onda ne iskoristiti to vreme da o istom trošku pronađe tačno jedan izjanđao token i, ako ga pronađe, sedne na njegovo mesto? Ovo mora da se odvija što je moguće brže tako da nijedan poziv metode `Store()` ne traje značajno duže od bilo kog drugog poziva. Imajmo u vidu da klijenti imaju slobodu da prozivaju naš interfejs pod kontrolom nekakvog tajmera, tako da bi bilo do jaja ako bi se ti pozivi odvijali glatko, bez značajnih razlika u dužini izvršavanja.

---

Pada na um jedna ideja. Ako bi u početku recimo imali prazan slajs neke početne dužine, a čiji bi članovi u početku svi bili `nil`, mogli bi taj slajs da obilazimo kao nekakav kružni bafer, jureći po njemu izjanđale tokene:

```go
    buffer := make([]*entry, initialCapacity)
    curr := 0
```

Algoritam bi išao nekako ovako:

1. Metoda `Store()`, budući da je mesto `buffer[curr]` u početku prazno ( `buffer[0] == nil`), jednostavno upiše kovertu sa `payload`-om u mapu, a na mestu `buffer[0]` ostavi strukturicu `entry` koja opisuje šta je u mapi sačuvano. Nakon toga, metoda `Store()` uveća `curr` za 1
2. Metoda nastavlja postupak iz 1. sve dok nailazi na prazna mesta, to jest dok ne dođe do kraja bafera. A kada dođe, ona prosto vrati `curr` na 0 i čeka sledeći poziv.
3. Budući da je `curr` sada opet 0, mesto `buffer[0]` sledećeg puta sigurno neće biti prazno. Međutim, znamo da će se na tom mestu nalaziti najstariji token. Ovo znači da baš taj token ima najveću šansu da bude izjanđao. 
4. Ako jeste izjanđao, onda ga jednostavno izbrišemo iz mape, a mesto `buffer[0]` prejašemo novom strukturicom `entry`. Naravno, `curr` opet povećamo za 1 odmah iza toga.
5. Metoda `Store()` nastavlja postupak iz 4. sve dok nailazi na izjanđale tokene. Na ovaj način se izjanđali tokeni brišu, a na njihovo mesto dolaze novi, mlađani tokeni.
6. Ipak, u zavisnosti od početne veličine bafera, metoda `Store()` će moguće jednom naleteti na važeći token. Šta sad?
7. Kada se to desi, to će biti znak da nam je bafer pun važećih tokena, i da izjanđalih tokena više nema. Drugim rečima, bafer valja proširiti. U tu svrhu, alociraćemo dvostruko duži nov bafer, što, videli smo, neizostavno dovodi do kopiranja elemenata iz starog u novi, te nakon postavljanja promenljive `curr` na prvo prazno mesto u novom baferu, nastaviti postupak vrativši se na 1.

Na ovaj način bismo osigurali da se izjanđali tokeni brišu. 

---

Iako sve ovo zvuči do jaja, ovde ipak ima nešto što to nije. Već smo videli da je u Go-u, kao uostalom i u drugim programskim jezicima sveta, nemoguće alocirati novi bafer bez tumbanja/kopiranja memorije. A kada se to desi, metoda `Store()` će vidno da štucne. Zavisno od količine tokena koji se moraju kopirati, ona će odavati utisak da se kod nje nešto značajno desilo. 

Stvarno, kako izgladiti ovu džombu?

##### Povezane liste

U pomoć nam priskaču povezane liste. Ako ste, kao ja, mislili da su povezane liste samo nešto što se uči u školi, evo prilike da se uverimo da one mogu da budu korisne i u praksi. 

Umesto u nekakvom slajsu, informacije o tokenima (`entry`-je) ćemo držati u jednoj kružnoj povezanoj listi, iliti kružnoj pantljičari. U kružnim povezanim listama, sledeći član od poslednjeg je prvi. U stvari, ovde je teško reći šta je prvo a šta poslednje; liči na traženje ćoška u okrugloj sobi, zar ne? 

Sve ostalo ćemo raditi isto kao i u algoritmu opisanom gore. Jedina je razlika što promenljiva `curr` ovog puta neće biti prirodan broj, nego pokazivač na tekući članak naše pantljičare. A umesto inkrementiranja promenljive `curr`, na sledeći ćemo prelaziti sa `curr = curr.next`

Najbitnija razlika nastaje kad naiđe situacija u kojoj listu treba produžiti. Za razliku od slajsa, kod povezanih lista ovo može i bez tumbanja memorije (*in-place reallocation*). Ako nam se u tom trenutku pri ruci zgodno nađe jedna ista takva lista, samo prazna (a pobrinućemo se da će da se nađe), sve što treba uraditi je "nalepiti" novu listu na staru, i tako dobiti dvostruko dužu listu takoreći bez utroška vremena. U vremenu izvršavanja, ovakve situacije će se doživljavati kao da se nisu ni desile.

Definisaćemo strukturu za članak naše pantljičare, koji ćemo ovde nostalgično nazvati `tokenRing`:

```go
type tokenRing struct {
    next  *tokenRing
    entry *entry
}
```

Primetimo da ova struktura ujedno predstavlja i celu pantljičaru: iz svakog njenog članka moguće ju je obići uzastopnim korišćenjem promenljive `next`.

Da bi kōd izgledao koliko-toliko uljudno, od rekvizita nam je potrebna fabrika praznih pantljičara. Ta fabrika bi trebalo da ima metodu `manufacture()`. Prvi put pozvana, `manufacture()` će vratiti praznu pantljičaru inicijalne dužine. Sledeći put, `manufacture()` će vratiti pantljičaru iste dužine kao prvi put. Ovo zato da bi naša pantljičara, nakon lepljenja nove na staru, postala dvostruko duža. Pri svim sledećim pozivima ove metode, vraćena pantljičara bi trebalo da bude dvostruko duža od prethodne.

Na ovaj način bi naša pantljičara, poput slajsova, eksponencijalnom brzinom nalazila potreban kapacitet. Nakon izvesnog broja lepljenja, pantljičara će u jednom trenutku postati dovoljno dugačka da algoritam opisan gore nailazi isključivo na izjanđale tokene: vreme potrebno da pantljičara obrne krug biće duže od očekivane dužine života tokena. U tom slučaju ćemo reći da je pantljičara postala stabilna u odnosu na količinu tokena sa kojom se suočavamo. Od tada, pantljičaru neće biti potrebno dalje produžavati.

I još nešto: efikasnosti radi, svaki put kad fabrika primi narudžbu za novu pantljičaru (preko poziva metode `manufacture()`), neposredno pre isporuke fabrika će lansirati go-rutinu koja će u odvojenoj niti praviti još jednu, noviju. Za vreme koje je potrebno da se isporučena pantljičara potroši, sve su šanse da će ta još novija biti spremna za isporuku kad na to dođe red. Na ovaj način, prelaz sa stare na novu pantljičaru biće gladak.

Struktura potrebna za implementaciju fabrike pantljičara izgleda ovako:

```go
type tokenRingFactory struct {
    initialCapacity int
    demandCounter   int
    spareChannel    chan *tokenRing
}
```

- `initialCapacity`: početna dužina pantljičare. Svaka proizvedena pantljičara imaće dužinu koja je umnožak ovog broja.
- `demandCounter`: brojač. Svaki put kad fabrika isporuči pantljičaru, brojač se uvećava za 1.
- `spareChannel`: kanal (magacin) u kojem držimo pantljičare spremne za isporuku. 

Lep je običaj da se čak i za ovakve privatne strukture pišu konstruktori, da ne bi morali da lupamo glavu kako da ih inicijalizujemo. Ovo je naročito bitno kod ove strukture, jer nije lako videti da brojač na početku treba inicijalizovati na -1, a da kapacitet kanala `spareChannel` treba da bude 2:

```go
func newTokenRingFactory(initialCapacity int) *tokenRingFactory {
    ch := make(chan *tokenRing, 2)
    return &tokenRingFactory{initialCapacity: initialCapacity, spareChannel: ch, demandCounter: -1}
}
```

Primetite (mapnu) sintaksu građenja instance ove strukture. Ako ne želite da vodite računa o redosledu elemenata, ovako ih možete prozivati po imenu, pa redosled nije važan. Osim toga, neke elemente na ovaj način možete da izostavite, što sa rednom sintaksom koju smo ranije koristili nije bio slučaj.

Metoda `manufacture()` izgleda ovako:

```go
func (fct *tokenRingFactory) manufacture() *tokenRing {
    makeNew := func() {
        first := &tokenRing{}
        last := first
        capacity := pow2(fct.demandCounter) * fct.initialCapacity
        for i := 0; i < capacity-1; i++ {
            last.next = &tokenRing{last, nil}
            last = last.next
        }
        last.next = first
        fct.demandCounter++
        fct.spareChannel <- first
    }
    if fct.demandCounter < 0 {
        makeNew()
    }
    go makeNew()
    return <-fct.spareChannel
}

func pow2(y int) int {
    if y <= 0 {
        return 1
    }
    return 2 * pow2(y-1)
}
```

Anonimna funkcija `makeNew` u petlji pravi pantljičaru kapaciteta koji je došao na red, sastavi joj glavu i rep, te je ugura u kanal `spareChannel`. Pantljičare se isporučuju čitanjem iz ovog kanala. 

Primetimo sledeće parče koda:

```go
    if fct.demandCounter < 0 {
        makeNew()
    }
```

Promenljiva `demandCounter` će inicijalno biti -1, u kom slučaju nam odmah valja početi praviti pantljičaru, budući da do sada nijednu nismo nit' napravili, nit' isporučili. Na ovaj način će jedna pantljičara biti spremna za isporuku odmah iza `if`-a.

Sada lansiramo go-rutinu da nam napravi još jednu, rezervnu, i za vreme dok ona to još radi, vraćamo onu koju je već spremna. To činimo čitanjem iz magacina `spareChannel`. Ovo je razlog što kapacitet kanala treba da bude 2.

```go
    go makeNew()
    return <-fct.spareChannel
```

Na kraju, zamijetimo funkciju `pow2()`: ona vraća stepen dvojke... dobro, karte su ovde malkice nameštene, jer za negativne argumente ona vraća keca umesto nekakav razlomak. Ovo je da bi tempirali kapacitet pantljičara prema našim potrebama. Doduše, Go ima nekakvo stepenovanje u `math`-paketu, ali samo za realne brojeve. Otuda `pow2()` :angry: 

---

Sad kada imamo fabriku pantljičara, ostatak je laganica. Dodajmo na postojeću strukturu  `tokenStore` elemente `curr`, `prev` i `tokenRingFactory`:

```go
type tokenStore struct {
    syncedMapStore
    ttl              time.Duration
    curr             *tokenRing
    prev             *tokenRing
    tokenRingFactory *tokenRingFactory
}
```

Konstruktor za `tokenStore` izmenićemo da izgleda ovako:

```go
const defaultInitialCapacity = 1024

func NewTokenStore(ttl time.Duration, initialCapacity int) Store {
    if initialCapacity <= 1 {
        initialCapacity = defaultInitialCapacity
    }
    mu := sync.RWMutex{}
    syncedMapStore := syncedMapStore{mapStore{}, &mu}
    factory := newTokenRingFactory(initialCapacity)
    prev := factory.manufacture()
    curr := prev.next
    return &tokenStore{syncedMapStore, ttl, curr, prev, factory}
}
```

Ovde je valjda sve jasno. Primetimo samo da smo metodu `Fetch()` davno napisali negde gore u tekstu. Kako ona ne koristi nove elemente `curr`, `prev` i `tokenRingFactory`, ona ostaje takva kakva je bila. Ostaje samo da napišemo novu verziju metode `Store()`. Ona sada izgleda ovako:

```go
func (ts *tokenStore) Store(payload interface{}) (string, error) {
    envelope := envelope{payload, time.Now(), ts.ttl}
    return ts.store(&envelope)
}
```

Kao što vidimo, ovde glavni posao radi privatna metoda `store()`, što znači da u stvari nju treba disecirati:

```go
func (ts *tokenStore) store(envelope *envelope) (string, error) {
    token, err := ts.syncedMapStore.Store(*envelope)
    if err != nil {
        return "", err
    }
    entry := entry{token, envelope}
    storeAndBudge := func() {
        ts.curr.entry = &entry
        ts.prev = ts.curr
        ts.curr = ts.curr.next
    }
    ts.mu.Lock()
    defer ts.mu.Unlock()
    if e := ts.curr.entry; e == nil {
        storeAndBudge()
        return token, nil
    }
    if e := ts.curr.entry.envelope; e.expired() {
        delete(ts.mapstore, ts.curr.entry.token)
        storeAndBudge()
        return token, nil
    }
    ts.expandTokenRing()
    storeAndBudge()
    return token, nil
}
```

Ova funkcija, prvo što uradi, jeste da zove nasleđenu metodu `Store()` iz `syncedMapStore`, sačuvavši tako zadatu kovertu. Primetimo da nam ovde ne treba sinhronizacija, jer `syncedMapStore` to već radi. Ali isto tako primetimo da nakon ove linije, muteks iz `syncedMapStore` će biti otključan. Ovo znači da ćemo ga morati ponovo zaključati čim krenemo da radimo sa promenljivima koje su vidljive i iz drugih niti/*thread*-ova.

Nakon provere greške `err`, metoda konstruiše novi `entry` za sačuvavanje, a zatim odmah definiše anonimnu funkciju `storeAndBudge` koja, osim što sačuvava taj `entry`, mrda tekući članak pantljičare za jedno mesto. Ova funkcijica će se ovde pozivati sa više mesta u glavnoj funkciji, pa smo je zato izdvojili u poseban *closure*. Primetimo da je ovo samo definicija funkcije; ovde se ništa konkretno još ne izvršava:
```go
    entry := entry{token, envelope}
    storeAndBudge := func() {
        ts.curr.entry = &entry
        ts.prev = ts.curr
        ts.curr = ts.curr.next
    }
```

Tek sada nailazi mesto gde imamo potrebu da eksplicitno zaključamo muteks. Uvek zaključavajte muteks tačno onda kada za to imate potrebu, ni pre ni kasnije, a otključavajte ga čim možete. Nemojte, kao neki, zaključavati muteks na početku, za svaki slučaj, a otključavati ga na kraju, opet za svaki slučaj. Ovo utiče na propulzivnost vaših niti (*thread*-ova), smanjujući im mogućnost da se prirodno prepliću. 

Zamislite gosta kako ulazi u bar, a barmen, videvši ga na vratima, odmah "zaključa" bar samo za njega. Onda gost, umesto da naruči nešto, ode prvo u klonju da šora. Zatim dođe neki drugi gost i sa vrata vikne pivo, a barmen ga ljubazno obavesti da će morati da sačeka, i da će biti uslužen čim se onaj prvi gost vrati iz klonje i bude uslužen. Ovo ne bi bilo baš uredno, zar ne?

Muteks zaključavamo samo onda kada radimo sa promenljavima koje vide druge niti(*thread*-ovi). Budući da od sada pa do kraja funkcije radimo samo sa takvima, otključavnje muteksa odmah skidamo sqrca naredbom `defer`:

```go
    ts.mu.Lock()
    defer ts.mu.Unlock()
```

A sada, algoritam: prvo što proveravamo jeste da li je tekuće mesto u pantljičari prazno. Ako jeste, snesemo na to mesto naš `entry` i pomerimo se za jedno mesto, nakon čega vraćamo token:
 
```go
    if e := ts.curr.entry; e == nil {
        storeAndBudge()
        return token, nil
    }
```

Ako tekuće mesto ipak nije prazno, proveravamo da li je token koji smo tamo našli izjanđao. Ako jeste, brišemo ga iz mape, a onda isto kao malopre: 
```go
    if e := ts.curr.entry.envelope; e.expired() {
        delete(ts.mapstore, ts.curr.entry.token)
        storeAndBudge()
        return token, nil
    }
```

Neko će se možda ovde zapitati: kada se ovo desi, a šta smo ovde uradili sa starim `entry`-jem kojeg smo našli u pantljičari?

U Go-u, taj `entry` nit' znamo kako, nit' možemo eksplicitno da brišemo. Zato ga prosto pregazimo, k'o pijan balegu. Ovim će pregaženi `entry` izgubiti svoju poslednju referencu, pa će mu Go-ov `garabage collector` kad-tad smrsiti konce, dokrajčivši ga. Stvar je u tome što i Go, poput Javašluka, ima *garbage collector*, tako da se ne morate zezati sa životnim ciklusom promenljivih koje kreirate.

Ostaje da se vidi šta ako nije ništa od ovog dvoje (to jest ako se na tekućem mestu nalazi nit' prazan, nit' izjanđao token, nego važeći)?

U tom slučaju, to bi značilo da nam je ponestalo mesta za nove tokene, pa pantljičaru valja produžiti. To činimo pozivom metode `expandTokenRing()`:

```go
    ts.expandTokenRing()
```

Čim je pantljičara produžena, na prazno mesto na kojem se posle toga nalazimo prosto snesemo naš `entry`, pa vratimo token.

```go
    storeAndBudge()
    return token, nil
```

I to bi bilo to. Sve što preostaje da se pogleda je kako šljaka `expandTokenRing()`. Ova funkcija je kratka da skoro i ne zaslužuje da bude funkcija. Ipak, ponekad valja i jednu jedinu liniju koda zamotati u funkciju, ako je tako čitljivije:

```go
func (ts *TokenStore) expandTokenRing() {
    last := ts.tokenRingFactory.manufacture()
    first := last.next
    last.next = ts.curr
    ts.prev.next = first
    ts.curr = first
}
```

Funkcija `expandTokenRing()` prvo naruči novu kružnu pantljičaru, te joj odabere dva uzastopna članka za `first` i `last`. Ovde moramo povesti računa da sledeći od `last` mora da bude `first`, da bi pantljičara bila kružna, što objašnjava čudnoću toga da smo `first` dobili kao sledeći od `last`. Budući da pantljičara sama sebi grize rep, ovo na drugi pogled i nije čudno:

```go
    last := ts.tokenRingFactory.manufacture()
    first := last.next
```

Novu pantljičaru želimo kidati baš na ovom mestu, da bi je nastavili na staru. 

Dalje: mi znamo da članak `curr` stare pantljičare pokazuje na najstariji token. Za ovaj token znamo i to da je validan; u suprotnom, pantljičaru ne bi ni produžavali. Međutim, mi isto tako znamo da prethodnik od `curr` sadrži najmlađi token, jer je to poslednji token koji smo pantljičari ikada dodali. Staru pantljičaru želimo precvikati baš na tom mestu, i nastaviti je na novu. Ovo je razlog što smo u algoritmu gore dužnosno pamtili prethodnika od `curr` svaki put kad `curr` mrdne za jedno mesto (u promenljivoj `prev`).

Sada je laganica. Pantljičare spajamo tako što poslednji element nove pantljičare želimo da se produži u `curr`, a prethodnik od `curr` u staroj pantljičari (što je kod nas `prev`) želimo da se produži u prvi element nove pantljičare `first`. Na ovaj način čuvamo hronologiju tokena, tako da će najstariji token opet prvi doći na red čim se ovaj novi prilepak potroši:

```go
    last.next = ts.curr
    ts.prev.next = first
```

Ostaje da `curr` pomerimo tako da pokazuje na prvo prazno mesto u prilepku...

```go
    ts.curr = first
```

... i to bi bilo to. Ostaju nam unit-testovi, a njih nikada ne treba preskakati :smile:

##### Unit-testovi za `tokenStore`

Neki shvataju unit-testove kao prioritet, i pišu ih pre nego što napišu i redak korisnog koda. Naravno, ovakvi testovi u početku nema šanse da prođu, ali se stanje vremenom popravlja dodavanjem korisnog koda. Svaka čast onom ko ovako može.

Neki shvataju unit-testove kao moranje, i pišu ih tek na kraju. Mislim da ovo nije baš pametno. I programeri su ljudi, te kad jednom završe koristan rad, u opasnosti su da samo zbrljaju par unit-testova na kraju, čisto da umire savest. Da bi pokrivenost koda testovima dostigla prihvatljiv nivo, ovde je potrebna velika količina samodiscipline i volje da se, nakon završenog posla, napravi još jedan dodatni iskorak. Zato svaka čast onom ko ovako može.

Meni lično su unit-testovi zabava, jer na taj način podvrgavam kod iskušenjima koja se u praksi retko dešavaju. Nešto kao kad testiraju građevinu za opterećenja na koja se u praksi ne nailazi. Ja uvek počnem sa pisanjem korisnog koda, ali čim mi se zaokruži neka funkcionalnost, ja odmah dodam unit test za to jer me zabavlja da vidim kako radi.

Prvi test koji ćemo ovde napisati testira `ringFactory`, proveravajući da li mu kapacitet raste na planiran način. Dodajte novi fajl `token/tokenstore_test.go`, pa napišite sledeće:

```go
const initialCapacity = 5
const unexpectedRingCapacity = "unexpected ring capacity: expected %v, got %v"
func TestRingFactory(t *testing.T) {
    factory := newTokenRingFactory(initialCapacity)
    ring := factory.manufacture()
    checkCount(t, ring, nil, initialCapacity, unexpectedRingCapacity)
    ring = factory.manufacture()
    checkCount(t, ring, nil, initialCapacity, unexpectedRingCapacity)
    ring = factory.manufacture()
    checkCount(t, ring, nil, 2*initialCapacity, unexpectedRingCapacity)
    ring = factory.manufacture()
    checkCount(t, ring, nil, 4*initialCapacity, unexpectedRingCapacity)
    ring = factory.manufacture()
    checkCount(t, ring, nil, 8*initialCapacity, unexpectedRingCapacity)
    ring = factory.manufacture()
    checkCount(t, ring, nil, 16*initialCapacity, unexpectedRingCapacity)
}
```

Ovde smo koristili pomoćnu funkciju `checkCount` koja upoređuje broj članaka u pantljičari sa očekivanom vrednošću:
```go
func checkCount(t *testing.T, ring *tokenRing, filter func(tr *tokenRing) bool, expected int, msg string) {
    if l := ring.count(filter); l != expected {
        t.Fatalf(msg, expected, l)
    }
}
```
Metoda `count` koja se koristi gore vraća dužinu pantljičare, brojeći joj članke na ruke. Primetimo da metoda prima funkciju `filter` kao argument. Ovo će nam kasnije pomoći da u pantljičari prebrojimo važeće tokene. Ako je `filter`, kao u kodu gore, jednak `nil`, to je znak da nema filtriranja:

```go
func (r *tokenRing) count(filter func(tr *tokenRing) bool) int {
    curr, l := r, 0
    for curr.next != r {
        if filter == nil || filter(curr.next) {
            l++
        }
        curr = curr.next
    }
    if filter == nil || filter(curr.next) {
        l++
    }
    return l
}
```

Korisno je zapaziti da smo metodu `count` nalepili na `*tokenRing` u test-fajlu, a ne u fajlu gde `*tokenRing` inače stanuje. Ovo je moguće jer nam se unit-testovi nalaze u istom paketu kao i `tokenRing`, a šta se nalazi u kom fajlu u okviru istog paketa nije mnogo bitno. Ipak, kad jednom iskompajliramo glavni program naredbom `go build`, mislim da ova metoda neće biti ulinkovana. Ona je tu samo za potrebe unit-testa, a ovo bi Go trebalo da zna.

Osim toga, primetimo liniju:
```go
    curr, l := r, 0
```

Ovako se u Go-u mogu inicijalizovati više promenljivih u jednoj liniji, što je ponekad zgodno.

---

Sada ćemo dodati unit-test koji proverava da li `tokenStore` radi prema specifikaciji. Drugim rečima, da li zna da išta sačuva i vrati, kao i to da li se korektno ponaša kad tokeni izjanđaju? Opšte pravilo za količinu kojekakvih provera po unit-testovima glasi: **što više - to bolje!** Zato se ovaj test ne zadovoljava samo proverom da li metode `Store()` i `Fetch()` rade, nego proverava sve što je usput uopšte moguće proveriti, pa nam zbog toga unit-test izgleda ovako (disekcija sledi):

```go
const ttl = time.Duration(500 * time.Millisecond)
const initialCapacity = 5
const unexpectedCountOfValidEntries = "unexpected count of valid entries: expected %v, got %v"
const unexpectedLengthOfEntryMap = "unexpected length of the entry map: expected %v, got %v"

func TestTokenStoreFetch(t *testing.T) {
    store := NewTokenStore(ttl, initialCapacity)
    tokenStore, _ := store.(*tokenStore)
    var token string
    var err error
    for i := 0; i < initialCapacity; i++ {
        token, err = store.Store("something" + string(i))
        if err != nil {
            t.Fatal(err)
        }
    }
    checkCount(t, tokenStore.curr, filterValid, initialCapacity, unexpectedCountOfValidEntries)
    checkCount(t, tokenStore.curr, nil, initialCapacity, unexpectedRingCapacity)
    time.Sleep(ttl)
    expiredProbe, err := store.Fetch(token)
    if err == nil {
        t.Fatal(fmt.Errorf("unexpectedly got valid token: %v:%v", token, expiredProbe))
    }
    if expiredProbe == nil {
        t.Fatal(fmt.Errorf("unexpectedly got nil payload for token %v", token))
    }
    expired := expiredProbe.(string)
    if expired != "something" + string(initialCapacity - 1) {
        t.Fatal(fmt.Errorf("got unexpected payload: %v:%v", token, expired))
    }
    key, err := store.Store("another")
    if err != nil {
        t.Fatal(err)
    }
    checkCount(t, tokenStore.curr, nil, initialCapacity, unexpectedRingCapacity)
    something, err := store.Fetch(key)
    if err != nil {
        t.Fatal(err)
    }
    s, ok := something.(string)
    if !ok {
        t.Fatal("unexpected type of stored object")
    }
    if s != "another" {
        t.Fatal("unexpected stored object returned")
    }
    if len(tokenStore.mapstore) != initialCapacity {
        t.Fatalf(unexpectedLengthOfEntryMap, initialCapacity, len(tokenStore.mapstore))
    }
    checkCount(t, tokenStore.curr, filterValid, 1, unexpectedCountOfValidEntries)
    for i := 0; i < initialCapacity; i++ {
        token, err = store.Store("somethingelse" + string(i))
        if err != nil {
            t.Fatal(err)
        }
    }
    checkCount(t, tokenStore.curr, filterValid, initialCapacity + 1, unexpectedCountOfValidEntries)
    checkCount(t, tokenStore.curr, nil, 2*initialCapacity, unexpectedRingCapacity)
}
```

Uh, ovo baš ispade dugačko :unamused: Iako je nekome možda čudnjikavo da mu je unit-test duži od korisnog koda, ovo je često baš tako.

Na početku napravimo novi `Store` i odmah ga "izlijemo" kao `tokenStore`, da bi mogli da mu brojimo creva. Ovo zato što promenljiva `store` sadrži instancu interfejsa `Store`, što znači da preko nje nemamo nikakav pristup unutrašnjim organima implementacije. Otuda potreba za izlivanjem ove promenljive u `tokenStore`:

```go
    store := NewTokenStore(ttl, initialCapacity)
    tokenStore, _ := store.(*tokenStore)
```

Primetimo da potrebu za livnicom kao ovom gore imamo samo u unit testovima, jer u njima ispitujemo ispravnost svega što smo napisali. Za prave potrošače našeg koda, instanca interfejsa `Store` je sve što im treba.

Sada `store` napunimo sa onoliko tokena koliki je njegov početni kapacitet, i prebrojimo ih na ruke, da bi im proverili brojno stanje:
```go
    var token string
    var err error
    for i := 0; i < initialCapacity; i++ {
        token, err = store.Store("something" + string(i))
        if err != nil {
            t.Fatal(err)
        }
    }
    checkCount(t, tokenStore.curr, filterValid, initialCapacity, unexpectedCountOfValidEntries)
    checkCount(t, tokenStore.curr, nil, initialCapacity, unexpectedRingCapacity)
```

Ovde smo koristili pomoćnu funkciju `filterValid` pri brojanju važećih tokena, koja izgleda ovako:

```go
func filterValid(tr *tokenRing) bool {
    if tr.entry == nil {
        return false
    }
    return !tr.entry.envelope.expired()
}
```
Go dopušta slanje funkcija kroz parametre, što je veoma, veoma zgodno :smile:

U sledećoj liniji malkice dremnemo, da bi svi tokeni koje smo do sada dodali istekli, a zatim u nekoliko linija koje slede proveravamo da li se metoda `Fetch()` korektno ponaša kod izjanđalih tokena. Ako token postoji, ali je istekao, `Fetch()` ipak treba da vrati korektan `payload`, ali i grešku:
```go
    time.Sleep(ttl)
    expiredProbe, err := store.Fetch(token)
    if err == nil {
        t.Fatal(fmt.Errorf("unexpectedly got valid token: %v:%v", token, expiredProbe))
    }
    if expiredProbe == nil {
        t.Fatal(fmt.Errorf("unexpectedly got nil payload for token %v", token))
    }
    expired := expiredProbe.(string)
    if expired != "something" + string(initialCapacity - 1) {
        t.Fatal(fmt.Errorf("got unexpected payload: %v:%v", token, expired))
    }
```
Nakon poslednje provere, dodajemo novi token i proveravamo da li se Fetch() korektno ponaša i onda kada je token još važeći: 
```go
    key, err := store.Store("another")
    something, err := store.Fetch(key)
    if err != nil {
        t.Fatal(err)
    }
    s, ok := something.(string)
    if !ok {
        t.Fatal("unexpected type of stored object")
    }
    if s != "another" {
        t.Fatal("unexpected stored object returned")
    }
```
Sada proveravamo veličinu naše mape. Za očekivati je da ona ima isti broj elemenata kao pre, jer je ovaj najnoviji token seo na mesto jednog starog. Osim toga, proveravamo da je broj važećih tokena sada 1:
```go
    if len(tokenStore.mapstore) != initialCapacity {
        t.Fatalf(unexpectedLengthOfEntryMap, initialCapacity, len(tokenStore.mapstore))
    }
    checkCount(t, tokenStore.curr, filterValid, 1, unexpectedCountOfValidEntries)
```

Ali muke za `tokenStore` ovim još nisu završene. Sada ćemo dodati izvestan broj novih tokena, da proverimo da li nam je broj važećih tokena očekivan. Osim toga, budući da je sada očekivani broj važećih tokena za 1 veći nego početna dužina pantljičare, proveravamo da li je pantljičara duplirala svoj kapacitet:

```go
    for i := 0; i < initialCapacity; i++ {
        token, err = store.Store("somethingelse" + string(i))
        if err != nil {
            t.Fatal(err)
        }
    }
    checkCount(t, tokenStore.curr, filterValid, initialCapacity + 1, unexpectedCountOfValidEntries)
    checkCount(t, tokenStore.curr, nil, 2*initialCapacity, unexpectedRingCapacity)
```

Ovim smo završili proveru ponašanja `tokenStore`, proveravajući usput i izvestan broj drugih očekivanja. Ako *sve ovo* prođe na testu, to je dokaz (dobro, ne baš dokaz, ali svakako dobar argument) da je `tokenStore` lepo naučio svoju ulogu, i da ga je moguće koristiti u produkciji. Ako bismo sad izvršili unit-testove, dobili bismo sledeći rezultat:
```
$ go test -v
=== RUN   TestMapStoreFetch
--- PASS: TestMapStoreFetch (0.00s)
=== RUN   TestSyncedMapStore
--- PASS: TestSyncedMapStore (0.10s)
=== RUN   TestRingFactory
--- PASS: TestRingFactory (0.00s)
=== RUN   TestTokenStoreFetch
--- PASS: TestTokenStoreFetch (0.50s)
PASS
ok      github.com/ogou/token    0.432s
```

---

Međutim, nije lako usuditi se pustiti ovo u produkciju bez provere da li je `tokenStore` *thread-safe*. 

Kad god pišete nešto što bi prema specifikaciji trebalo da bude *thread safe*, napišite unit-test koji baš to proverava. Lansirajte mnogo paralelnih go-rutina koje će nemilosrdno drndati vaš kod, i proverite šta se dešava. Nije potrebno da takav test proverava korektnost dobijenih rezultata (takav test bi trebalo da ste već napisali), nego samo to da vam ništa neće pući, kao i to da će se sve go-rutine vratiti svom Tvorcu. 

Srećom, ovakve stvari u Go-u su laganica. Unit-test za *thread safety* naći ćete dole. I to sa jednim malim dodatkom: budući da nam je usput, u ovom testu proveravamo da li nam se dužina dobijenih `tokenRing`-ova uklapa sa brojem poziva metode `Store()`:

```go
func TestTokenStoreConcurrency(t *testing.T) {
    var concurrencyTests = []struct {
        volume             int
        expectedRingLength int
    }{
        {10, 10},
        {11, 20},
        {20, 20},
        {21, 40},
        {39, 40},
        {40, 40},
        {41, 80},
        {80, 80},
        {81, 160},
        {100, 160},
        {161, 320},
        {321, 640},
        {640, 640},
        {641, 1280},
        {1281, 2 * 1280},
        {2 * 1281, 4 * 1280},
    }
    for i := 0; i < len(concurrencyTests); i++ {
        testTokenStoreConcurrency(t, concurrencyTests[i].volume, concurrencyTests[i].expectedRingLength)
    }
}
```

Ovde smo definisali niz anonimnih struktura koje sadrže broj niti (*thread*-ova) koje će navaliti da prozivaju `Store()`, kao i očekivanu dužinu pantljičare nakon što sve niti završe svoj posao.

Primetimo još nešto: brojeve iz gornje tabele smo računali napamet, uzimajući u obzir činjenicu da je konstanta `initialCapacity` definisana kao `5`. Ako bi ovu konstantu najednom promenili, ovaj unit-test ne bi prošao. Čistunci bi rekli da bi očekivane dužine pantljičara trebalo da zavise od ove konstante ako želimo da kod bude korektan, pa se postavlja pitanje: zašto smo to ovako uradili?

Ono što u opštem slučaju nije dopušteno u glavnom kodu, često je dopušteno u unit-testovima. Svrha unit-testova nije da prođu za svaku vrednost konstanti koje smo birali, nego da dignu uzbunu kad god im se učini nešto sumnjivo. Ako bi konstantu `initialCapacity` zaista promenili, ovaj test bi pukao, što je i cilj. To bi bio signal programeru da mu valja ponovo preračunati brojeve iz one tabele, prilagodivši ih novoj vrednosti konstante `initialCapacity`. A ako mu to jednog dana dosadi, lenji programer bi mogao čistunski promeniti gornji kod da zaista zavisi od `initialCapacity`, ali to je sada druga priča.

Vidimo da ovde glavni posao radi funkcija `testTokenStoreConcurrency()` koja izgleda ovako (disekcija sledi):

```go
func testTokenStoreConcurrency(t *testing.T, volume int, expected int) {
    store := NewTokenStore(ttl, initialCapacity)
    mem, _ := store.(*TokenStore)
    var wg sync.WaitGroup
    storeWrapper := func(wg *sync.WaitGroup) {
        defer wg.Done()
        random, _ := random()
        store.Store(random)
    }
    fetchWrapper := func(wg *sync.WaitGroup) {
        defer wg.Done()
        random, _ := random()
        store.Fetch(random)
    }
    start := time.Now()
    for i := 0; i < volume; i++ {
        wg.Add(1)
        go storeWrapper(&wg)
        wg.Add(1)
        go fetchWrapper(&wg)
    }
    ok := isDoneWithinTimeout(&wg, ttl)
    if !ok {
        t.Fatal("no all go routines finished within timeout")
    }
    checkCount(t, mem.curr, nil, expected, unexpectedRingCapacity)
    t.Logf("Stress test elapsed time: %v", time.Since(start))
}
```
Šta se ovde dešava?

Nakon što smo kreirali instancu interfejsa `Store()` i izlili je u `tokenStore` na poznat način, kreirali smo promenljivu `wg` tipa `sync.WaitGroup`:
```go
    var wg sync.WaitGroup
```
Promenljive ovog tipa su jako korisne kada treba brojati da li su se sve lansirane go-rutine vratile. Kad god lansiramo neku go-rutinu, neposredno pre toga pozovemo `wg.Add(1)`. Jednom kad lansiramo sve go-rutine koje smo nameravali lansirati, jednostavno pozovemo `wg.Wait()`. Ovaj poziv je blokirajući, što znači da će `wg` čekati da se sve go-rutine vrate.

E sad, kako `wg` zna da li se neka go-rutina vratila ili ne? 

Ovo valja malkice isprogramirati, ali je prosto kao pasulj. Svaki put kad pozovete `wg.Add(1)`, time ste ušli u dug za 1, a go rutine vas razdužuju tako što pozovu `wg.Done()`. To znači da će `wg.Wait()` čekati sve dok sve go-rutine ne overe svoj izlazak sa `wg.Done()`, koliko god da ih ima.

Budući da je `wg.Wait()` *ipak* blokirajući, i ovo valja zaštititi tajmerom. U tu svrhu nam služi pomoćna funkcija `isDoneWithinTimeout()` koja izgleda ovako:

```go
func isDoneWithinTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
    c := make(chan struct{})
    go func() {
        defer close(c)
        wg.Wait()
    }()
    select {
    case <-c:
        return true
    case <-time.After(timeout):
        return false
    }
}
```
Funkcija vraća `true` ukoliko je wg odblokirao u predviđenom roku. U suprotnom ona vraća `false`. Ostavljamo čitaocu da proanalizira kako ovo radi, budući da su svi elementi sada poznati.

Ostatak je prostakluk. Prvo deklarišemo dve anonimne funkcije koje će generisati slučajne pozive metoda `Store()` i `Fetch()`, ali koje neće zaboraviti da se razduže pozivajući `wg.Done()` na kraju:

```go
    storeWrapper := func(wg *sync.WaitGroup) {
        defer wg.Done()
        random, _ := random()
        store.Store(random)
    }
    fetchWrapper := func(wg *sync.WaitGroup) {
        defer wg.Done()
        random, _ := random()
        store.Fetch(random)
    }
```

Sada lansiramo go-rutine u petlji...
```go
    for i := 0; i < volume; i++ {
        wg.Add(1)
        go storeWrapper(&wg)
        wg.Add(1)
        go fetchWrapper(&wg)
    }
```
... a onda proverimo da li su se sve go-rutine vratile u predviđenom vremenu:
```go
    ok := isDoneWithinTimeout(&wg, ttl)
    if !ok {
        t.Fatal("no all go routines finished within timeout")
    }
```

Ako ovo prođe, imamo sve razloge da verujemo da je `tokenStore` *thread safe*. Kao što smo najavili, na kraju samo proveravamo da li nam je dužina pantljičare očekivana za datu količinu poziva metode `Store()`:
```go
checkCount(t, mem.curr, nil, expected, unexpectedRingCapacity)
```

---

Ovim smo završili unit-testove koje smo ovde nameravali napisati. Ako bismo ih sada izvršili, dobili bismo sledeći rezultat:

```
$ go test -v
=== RUN   TestMapStoreFetch
--- PASS: TestMapStoreFetch (0.00s)
=== RUN   TestSyncedMapStore
--- PASS: TestSyncedMapStore (0.10s)
=== RUN   TestRingFactory
--- PASS: TestRingFactory (0.00s)
=== RUN   TestTokenStoreFetch
--- PASS: TestTokenStoreFetch (0.50s)
=== RUN   TestTokenStoreConcurrency
--- PASS: TestTokenStoreConcurrency (0.06s)
    tokenstore_test.go:147: Stress test elapsed time: 300.61µs
    tokenstore_test.go:147: Stress test elapsed time: 384.504µs
    tokenstore_test.go:147: Stress test elapsed time: 479.724µs
    tokenstore_test.go:147: Stress test elapsed time: 525.335µs
    tokenstore_test.go:147: Stress test elapsed time: 883.037µs
    tokenstore_test.go:147: Stress test elapsed time: 641.688µs
    tokenstore_test.go:147: Stress test elapsed time: 617.994µs
    tokenstore_test.go:147: Stress test elapsed time: 1.322203ms
    tokenstore_test.go:147: Stress test elapsed time: 947.099µs
    tokenstore_test.go:147: Stress test elapsed time: 1.109345ms
    tokenstore_test.go:147: Stress test elapsed time: 1.681223ms
    tokenstore_test.go:147: Stress test elapsed time: 3.131412ms
    tokenstore_test.go:147: Stress test elapsed time: 5.82719ms
    tokenstore_test.go:147: Stress test elapsed time: 5.450642ms
    tokenstore_test.go:147: Stress test elapsed time: 13.473834ms
    tokenstore_test.go:147: Stress test elapsed time: 24.369628ms
PASS
ok      github.com/ogou/token    0.672s
```

###  Nešto za kraj: `main.main()`

Da bi ilustrovali kako se pišu izvršni programi, a ne samo biblioteke, ovaj repo sadrži jedan takav program. To je jedan jednostavan HTTP-serverčić koji dozovljava da se igramo onim što smo do sada napisali.

Ovde nećemo detaljno disecirati ovaj program; to istavljamo za vežbu. A ionako smo se previše raspisali. Reći ćemo samo to da se kod za ovo nalazi `main` paketu kojeg možete pogledati [ovde](https://github.com/gordost/ogou/blob/master/main/main.go)

Uputstvo kako da izgradite izvršni program se nalazi [ovde](https://github.com/gordost/ogou/blob/master/main/README.md)

###  Kuda dalje?

Na kraju, nameće se pitanje šta je to što ovde nema, a može da nam zafali? Ako čitalac ima vremena i volje, mogao bi da proba nešto od toga i sam da implementira (ne zaboravite *Pull Request*).

##### Različiti TTL-ovi

Ma koliko efikasan ovaj algoritam bio, upada u oči da on potpuno zavisi od toga da je TTL svih tokena uvek isti. Ali šta ako želimo da neke tokene sačuvamo sa jednim TTL-om, a neke druge sa nekim drugim? Drugim rečima, šta ako nam treba proširenje interfejsa `Store` definisano ovako:

```go
    type StoreWithTTL interface {
        Store
        func StoreWithTTL(payload interface, ttl time.Duration) (token string, err error)
    }
```

Primetimo ugnježdavajuću sintaksu, sličnu kao kod struktura. Na ovaj način, novi interfejs `StoreWithTTL` bi i dalje bio *assignment*-kompatibilan sa `Store`, ali bi imao dodatnu funkciju koja za neke tokene definiše nestandardan TTL.

---

Ovo ne bi trebalo biti mnogo teško napraviti, a ipak zadržati efikasnost algoritma iz `tokenStore`. Kao prvo, koliko različitih vrednosti TTL-a ćemo ikada imati? U praksi, obično se barata sa samo nekoliko: super kratki (nekoliko sekundi), malkice duži (nekoliko minuta), još duži (nekoliko sati), pa onda nekoliko dana, nedelja, meseci i tako dalje. U svakom slučaju, teško je zamislivo da ćemo ikada baratati sa TTL-ovima čije se vrednosti prostiru na više od, lupam, par stotina različitih. Ovo znači da i dalje možemo tokene držati u jednoj mapi, ali da umesto jednog `tokenRing`-a možemo imati mapu `tokenRing`-ova za različite TTL-ove:

```go
    var tokenRingMap map[time.Duration]*tokenRing
```
 
Fabriku tokenRingova bi valjalo prepraviti da bude ttl-*aware*, i uz malkice još nekih prepravki, to bi trebalo biti to.

##### Distribuirani TokenStore

Ako vaš *host* čini više različitih mašina koje rakolje iza nekakvog *load balancer*-a, neophodno je da sve mašine imaju isti sadržaj `tokenStore`-a, da bi stvar radila.

U tu svrhu, bilo bi zgodno da `tokenStore` hostuje nekakav HTTP (REST?) *end-point* kojim može da primi tokene koje su `tokenStore`-ovi sa drugih mašina kreirali, kao i publikovati tokene koje je sam kreirao. Uz to, bilo bi zgodno da se `tokenStore`-ovi sa različitih mašina sami pronalaze na mreži, bez ikakve dodatne konfiguracije, a i to da, čim se neka nova mašina pojavi, da ima načina da od starih mašina primi važeće tokene.

Ovde treba voditi računa o tipu podataka, jer payload-ove sa različitih mašina valja serijalizovati/deserijalizovati preko mreže. Možda `Json`?

##### Perzistentni TokenStore

Mašine se ponekad moraju restartovati, tako da bi isto tako bilo zgodno da TokenStore ima načina da serijalizuje svoj sadržaj u neku perzistentnu memoriju (recimo disk, mada i ovo treba biti konfigurabilno), tako da se nove instance `tokenStore`-ova mogu inicijalizovati recimo odatle.

##### StoreWithTTL kao keš

Interfejs `StoreWithTTL` je možda zgodno proširiti da prihvata tokene-strance, tako da isti softver može poslužiti i kao keš, ako treba:

```go
    type StoreWithKey interface {
        StoreWithTTL
        func StoreWithKeyAndTTL(key string, payload interface, ttl time.Duration) error
        func StoreWithKey(key string, payload interface) error
    }
```








