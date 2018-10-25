# Kraš-kurs iz Go-a jednog popizdelog Javašlučara

Evo već mesečak dana pišem isključivo u Go-u, pa reko' da promuhabetim nešto na tu temu. Zato odmah na startu da se izlajem: ako me išta bude nateralo da se vratim Javi, smatraću to korakom unazad. Program napisan u Go-u podseća na žilavog dugoprugaša koji zna i da poleti u sprint kad treba, a u Javi na ćelavog debeljka koji se u početku jedva vuče, premda kasnije hrabro gura kada se zalaufa. Stvar je u tome što su Javini frejmvorkovi, iako strogo nisu deo Jave, nekako postali nezaobilazni deo jezika. Kontrasta radi, minimalizam Go-a je razlog što je Go eksplodirao u Docker-kontejnerima i Lambda-servisima na AWS-u... brzo se startuje, i odmah navali da radi svoj pos'o.

Pošto me mrzi da izmišljam mnogo usiljenih primera, a ipak želim da ilustrujem jezik i lakoću paralelnog programiranja u Go-u, proći ćemo ovde kroz “algoritamčič” koji sam nedavno sklepao u vezi sa projektom na kome radim, a koji sam malkice izmenio za potrebe ovog pisanija. Ili bloga, jebemliga šta je. Ovo sve u nadi da če vam se Go dopasti kad završite čitanje. Na poređenja sa Javašlukom (kao i na prednosti Go-a u odnosu na Javašluk) nabasaćete u toku čitanja :smiley:

Treba imati u vidu da sam i ja još početnik u Go-u, te da tehnike opisane ovde možda nisu optimalne. A možda ima i grešaka. Svejedno, meni se Go toliko dopao da sam poželeo da o tome ima nešto više na našem jeziku.

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
E sad: u ove 4 linije (dobro, ajde, 6, ako ubrojimo komentar i zagradu) ima toliko informacija o jeziku da je teško prelomiti odakle krenuti. Da se ne bi previše zezali, krenimo redom.

### Paketi (packages)
```go
package token
```
U Go-u, kod se smešta u fajlove koje raspoređujete po direktorijumskom drvetu, da ne kažem baobabu. Zašto baobabu? Pa zato što će se sve što u Go-u napišete naći ispod jednog super-direktorijuma za koji je, verujte mi, najbolje da se zove `~/go/src/github.com`. Osim toga, svaki, pa i najtričaviji pod-direktorijumčić sa tog baobaba Go će smatrati svojom bibliotekom. Imajte u vidu da će se na istom baobabu naći i tuđe biblioteke, što znači da ovo zna da se razgrana do besvesti.

U Go-u, biblioteke se zovu paketi (`package`), tako da ova naredba daje našem paketu ime. Ime mora da se poklapa sa imenom pod-direktorijuma u kojem se paket nalazi. Imena fajlova u istom paketu (dobro, ajde, pod-direktorijumu) nisu bitna, ali treba da se završavaju sa `.go`. Konačni rezultat je ionako unija svih tih fajlova, tako da vam se isto 'vata ako paket napišete kao jedan jedini veliki fajl. Ipak, čitljivije je pakete razbijati u više fajlova, već prema značenju.

Primetite upotrebu VELIKIH slova u deklaraciji interfejsa `Store` i njegovih metoda. Ovo nije bezveze. Ako nešto (šta god) u datom paketu počinje velikim slovom, onda je to "nešto" vidljivo i iz drugih paketa. U Javašluku za to služi modifikator `public`, ali je meni ova ekonomičnost Go-a toliko seksi da prosto nemam reči. Kad se samo setim metričke tonaže modifikatora `public` i `private` u Javinim programima, padne mi mrak na oči, dok je u Go-u ovo mrak rešeno. Ako želite da vam u paketu nešto ostane privatno, koristite malo slovo. U suprotnom, koristite veliko. Kraj priče.

Kad smo već kod toga: ja nikad nisam istinski razumeo svrhu Javinog `private` modifikatora. Stvar je u tome što je u Javi nešto *public* ako upotrebite modifikator `public` u deklaraciji tog nečeg, a *private* ako upotrebite - `private`. Ali stvar se ovde ne završava. U Javi, nešto može da bude i `/*package private*/`. Iako za ovo ne postoji službena reč (nego samo komentar; mnogi javaši smatraju da za ovo treba da se uvede službena reč), u Javi je nešto `/*package private*/` ukoliko ne upotrebite nijedan od ona dva gorespomenuta modifikatora. U tom slučaju, to "nešto" će biti vidljivo unutar svog paketa, dok za sve druge pakete - neće! E sad: razumem to za`public`... razumem i to za `/*package private*/`, jer nam vidljivost unutar istog paketa treba... ali ne razumem koji će nam qurac `private`? Pa koji to imbecil želi nešto da krije od samog sebe? U Go-u je ovo ispravno rešeno tako što nešto počinje ili velikim ili malim slovom, i ćao zdravo!

### Interfejsi
```go
type Store interface {...}
```
Za gujone, interfejs je obećanje koje ispunjava onaj ko ga implementira (to jest onaj ko implementira sve metode navedene u njemu). Go, za razliku od Jave, nema klase, ali, eto, ima interfejse. Interfejsi su razlog što ni u jednom trenutku nisam doživeo "besklasnost" Go-a kao falinku. Evo već skoro dve decenije koristim Javu koja ne samo da ima klase, nego ima i to da u Javi ne možete da napišete ni redak korisnog koda van konteksta neke klase. Ipak, poslednjih godina sam često uhvatio sebe da se pitam koji će mi Javine klase? Već duže pišem Javin kod ravnajući se prema interfejsima, a klase, za koje me najčešće boli ona stvar, uglavnom koristim samo zato što je to u Javi moranje. Nasleđivanje sam odavno prestao da koristim (osim, naravno, ako se ne radi o nasleđivanju interfejsa), a omiljeni štos mi je anonimna implementacija interfejsa. U Javi, ovo je jedini način da izbegnete eksplicitnu deklariciju klase koja vam u stvari ne treba, pa valjda zato.

Naravno, nigde ne treba biti potpuno isključiv: iako za to postoje alternativne tehnike, i u Javi ponekad valja praviti klasne hijerarhije da ne bi morali da duplirate sopstveni kod. Ipak, model u kojem se prave (apstraktne) klasne hijerarhije *predviđene za nasleđivanje* je napušten. Vaše klasne hijerarhije, ako ih ima, treba da ostanu privatne unutar paketa gde su nastale, a svetu eksponirajte interfejse i (najbolje) statične metode koje na ovaj ili onaj način vraćaju tražene instance tih interfejsa. Dati nekome klasnu hijerarhiju za nasleđivanje je nepregledno i potencijalno opasno. A najčešće i nepotrebno, jer korisnik uvek može dobijene instance zaviti u neku svoju klasu, dekorišući ih.

Elem, izgleda da su autori Go-a i ovo ispravno uočili, pa su iz svog jezika najurili klase. Time su interfejsi postali jedna od najvažnijih jezičkih konstrukcija u Go-u. Na primer, pored interfejsa izlistanog gore, uočite tip parametra `payload` iz metode `Store`:
```go
	Store(payload interface{}) (token string, err error)
```

Ovaj parametar je tipa `interface{}`. U Go-u, tip `interface{}` označava prazan (pra-)interfejs koji svaki tip promenljivih u Go-u implementira. Ovo važi za tipove koje sami deklarišete, ali i za tipove koji su deo jezika (*built-in*). One dve vitičaste zagrade jedna odmah iza druge označavaju "praznoću" interfejsa, to jest da ovaj interfejs nema metode (i u matematici se oznaka `{}` često koristi za prazan skup). Zbog praznoće ovog interfejsa, ispada da je svaka promenljiva tipa `interface{}` *assignment*-kompatibilna sa promenljivom bilo kog drugog tipa. Ovo je prosto zato što je tvrđenje **SVE implementira NIŠTA** jedna valjana formula, zar ne? E sad, pošto smo skapirali ovo, u Go-u je moguće pisati:
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

Ovu dojajnost smo iskoristili u deklaraciji našeg interfejsa `Store`. Parametar i izlazna vrednost `payload` su namerno tipa `interface{}` baš zato što nas se nešto previše ne tiče **šta** nam je predato na čuvanje. U pravoj garderobi, nekad će to biti kaput, nekad jakna, a nekad će neka dobra riba tamo ostaviti svoju torbicu sa ... ajde da ne ulazimo u to šta ona sve tamo može da ima. Isto tako, ovaj interfejs i neku njegovu implementaciju možete koristiti za generisanje i čuvanje kukija u nekoj Web-aplikaciji, u kojoj će token biti vrednost kukija, a `payload` - status jedne sesije. U svakom slučaju, interfejs `Store` na ovaj način želi da se izjasni da ga boli uvo za prirodu objekta predatog mu na čuvanje, te da o tome treba da razmišlja vlasnik.

### Prvi pitonizam: višestruke povratne vrednosti iz funkcija

Eto polako dođosmo i do metoda gorenavedenog interfejsa. Primetite da one, sudeći po potpisu, trebaju da vrate dve stvari, a ne samo jednu:

```go
	Store(payload interface{}) (token string, err error)
	Fetch(token string) (payload interface{}, err error)
```

Ako me naterate da izdvojim nešto što mi je sve ove godine najviše išlo na onu stvar u Javi, odlučio bih se za to da Javine metode mogu da vrate samo jednu stvar. A ako vam zatreba više stvari, snalazite se kako znate. Ovo se svodi na uvođenje suštinski nepotrebnih Javinih klasa samo zato da bi u njih spakovali tih više stvari. U tu svrhu, već godinama koristim `org.apache.commons.lang3.tuple.Pair<L, R>` koji mi, eto, dozvoljava da u povratnu vrednost spakujem dve stvari. A kad mi zatreba treća, dolazi do rađanja mečke :rage:

U Go-u je prirodno da funkcija može da vrati više stvari odjednom; ovo je možda najpoznatiji idiom jezika. U našem slučaju, metoda `Store` vraća token i eventualnu grešku (`nil` ako nema greške), a metoda `Fetch` - payload i grešku. Primetite da smo povratne vrednosti u ovim metodama krstili nekakvim imenima, jer je u Go-u ovo moguće. Iako nije obavezno, ovo zna da bude jako korisno, čitljivosti radi, a to naročito važi za interfejse čiji pisac već u toku pisanja ima priliku da podari povratnim vrednostima svojih metoda nekakvu semantiku. Ovo će sigurno radovati čitaoce.

---

Sa stanovišta pozivača ovih metoda, ovaj tango izgleda nekako ovako, pod uslovom da u ruci imate nešto što implementira interfejs `Store` (a što se dole zove `store`):

```go
	something := "neki qrac"
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
Primetite konstrukciju `token, err := store.Store(something)`, a naročito operator dodeljivanja u njoj (`:=`). On se razlikuje od operatora dodeljivanja koji smo već koristili. Go je veoma strog jezik što se tiče tipova, ali kompajler je jedan kul lik koji podstiče programere na lenjost. U Go-u, postoji više načina da deklarišemo promenljivu `something` i dodelimo joj vrednost:
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

---

```go
const tokenLength = 5
```
Da ne žvalavimo previše, ovako se u Go-u definišu konstante. Za standardnu dužinu tokena odabrali smo 5, jer nam treba nešto kratko da nam je golim okom čitljivo, ali ne i prekratko, da bi broj mogućih tokena bio dovoljno veliki. Kod nas je ovaj broj 62 na peti stepen, što je jednako 916 132 832. Znači šanse da neko iz dupeta izvuče važeći token su male.

---

```go
var tokenLetters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
```

Evo najzad jednog pravog pravcatog niza. Dobro, ajde, slajsa, da budemo precizni, ali to je u Go-u skoro isti q.

##### Drugi pitonizam: nizovi i kriške (slices)

Nizovi su važni u svakom jeziku, pa ćemo se ovde malkice zadržati. Prvo recimo to da mi ovde želimo da nam tokeni budu čitljivi, pa smo `tokenLetters` inicijalizovali znakovima koje želimo da vidimo u našim tokenima, izbacivši karakondžule. Ipak, ova linija definiše slajs, a ne niz. Ako želimo pravi niz, njega bismo morali dobiti nekako ovako:

```go
var tokenLetters [62]byte = [62]byte('a','b','c','d','e' ... ,'9') 
```

Ili malkice kraće, jer se tip ovde može izostaviti:

```go
var tokenLetters = [62]byte('a','b','c','d','e' ... ,'9') 
```

###### Kriške (slices)

Nizovi u Go-u su kao nizovi u svim drugim jezicima. Oni imaju određenu (unapred deklarisanu) dužinu, i sadrže elemente istog tipa. U prethodna dva primera smo deklarisali niz od 62 `byte`-elementa, a onda smo ga napunili `byte`-ovima već u deklaraciji. U pred-pred-prethodnom primeru smo učinili skoro istu stvar, samo što smo tada bili malkice lenji, pa smo samo konvertovali onaj string-literal (ili *bukval*, kako ovo prevesti, jebemliga?) u seriju bajtova, da ne bi morali ručno da ih brojimo i da tako dođemo do broja 62. 

E sad, zbog unapred određene dužine, nizovi u svim jezicima su teški kao slonovi. Zamislite da vam u jednom trenutku zatreba podniz (koji je isto tako, tipski gledano, niz) koji obuhvata sve od 5-tog do 55-tog elementa onog niza gore. Ako bi u jeziku imali isključivo nizove, za taj podniz morali bi alocirati novi niz od 50 elemenata i kopirati potreban sadržaj, da bi tako dobili traženu strukturu. E sad, nagradno pitanje: ne bi li bilo zgodno ako taj novi niz ne bi morali niti alocirati, niti kopirati, nego ga samo nekako prišljamčiti uz onaj stari, da ga yebem kako, ali ako znamo da je sve što nam je potrebno **već** tamo, to bi valjda trebalo biti moguće, zar ne?

Ovde na scenu uskaču kriške (slices). Slajs je prozor kroz koji gledamo niz koji se nalazi u pozadini slajsa. Kroz taj prozor možemo da vidimo ceo niz, a možemo i samo parče (krišku). Stvar je u tome što svaki slajs mora u pozadini imati jedan pravi niz, i taj niz ćemo ovde zvati *niz-pozadinac*. Zbog ove osobine, slajsovi imaju lakašnu strukturu: jedan pokazivač na niz-pozadinca, plus informaciju o lokaciji i veličini prozora. Zbog toga su sve operacije sa slajsovima brze k'o guja. Na primer, za niz `tokenLetters`, slajs koji se sastoji od 5-tog do 55-tog elementa tog niza, a bez ikakvog tumbanja memorije, dobijamo ovako:

```go
	s := tokenLetters[5:56] // 56-ti nije uključen
```

---

Konstruišimo sada jedan pravi niz, da imamo šta da drndamo u primerima, ali koji neće biti predugačak, zbog ispisa:

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
Ovo `a` je sada bio pravi niz, a ne slajs. Ponekad to nije lako videti. Stvarno, kako prepoznati razliku? Odmah da kažem da je pitanje na mestu: u Go-u, nizovi i slajsovi se sa stanovišta rada sa njima sasvim malo razlikuju. Ipak, da bi serija nečega bila niz (a ne slajs), potrebno je da joj se u onim uglastim zagradama deklaracije nađe konkretna informacija o tome koliko toga nečega ima, kao što je slučaj sa `[10]int`. Čim tu informaciju izostavite, i upotrebite prazne uglaste zagrade, kao `[]int`, na ovaj ili onaj način dobili ste slajs. Ovo je razlog što je `var tokenLetters = []byte("abc..")` bio slajs.

Izvucimo sada iz niza `a` slajs koji "posmatra" prvih pet članova tog niza, i odštampajmo mu `len()` i `cap()`
```go
    s := a[:5]
    fmt.Println(s, len(s), cap(s)) 
```
```
    [0 1 2 3 4] 5 10
```
Sintaksa je kao u Pitonu. Prazno mesto ispred dvotačke znači od početka, broj 5 iza dvotačke znači 5 komada od početka niza. Slično, `a[:]` bi bio slajs koji posmatra ceo niz, a `a[5:]` bi bio slajs koji posmatra podniz of 5-tog elementa do kraja niza. Za razliku od Pitona, Go ne trpi negativne brojeve u indeksiranju slajsova, ali dobro.

Na osnovu `cap()`-a (koji je ovde 10), vidimo da je Go ispravno zaključio da je niz-pozadinac ovog novog slajsa naš očenj poznati niz `a`. Ovo je jasno jer smo baš iz njega "izvukli" elemente za `s`. To ujedno znači da `s`, iako ima dužinu 5, ima prostor da širi svoj prozor sve do 10. Proverimo ovo jednom malkice perverznom naredbom kojom ćemo od slajsa `s` zatražiti nešto što ovaj na prvi pogled nema:
```go
    s2 := s[3:7]
    fmt.Println(s2, len(s2), cap(s2))
```
```
    [3 4 5 6] 4 7
```
Ispada da je `s` odnekle izvukao nešto što naizgled nema, sudeći prema ispisu gore. Ali ovo uparvo znači da je slajs `s` zaista samo prozor kroz koji se posmatra niz-pozadinac `a`, i da je rastegljiv do kapaciteta potonjeg. Potvrdimo ovo tako što ćemo izmeniti nešto u slajsu `s`, pa proveriti da li je ta izmena imala efekat na niz-pozadinca, ali i na slajs `s2`, jer je i on baziran na istom:
```go
    s[3] = 3000
    fmt.Println(a) 
    fmt.Println(s2)
```
```
    [0 1 2 3000 4 5 6 7 8 9]
    [3000 4 5 6]
```
Ispada da jeste. Zapamtite: kad god menjate nešto u slajsu, Go će pokušati da za to drnda niz-pozadinca. A ako zbog nečeg to ne može (uglavnom zbog kapaciteta pozadinca), Go će naći novog mršu za drndanje. Proverimo ovo u dva koraka.

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

A sad, prc: izvucimo novi slajs `y` dodavanjem još jednog elementa na `x`. Očekujemo da Go više neće biti u stanju da drnda starog niz-pozadinca za potrebe slajsa `y`, jer ovaj više nema za to potreban kapacitet, i da će biti prinuđen izmisliti novog niz-pozadinca, da bi na njemu temeljio `y`:
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

Da bi zadovoljio `y`, Go je izmislio novog niz-pozadinca za `y`. Primetimo da mi tom novom nizu-pozadincu ne ne znamo čak ni ime. Pitanje glasi: a gde je sad pa **taj** niz, i kako mu prići? I da li uopšte treba da mu prilazimo? I ako ne, zašto?

Iako i za to postoje tehnike (`package reflect`), mi se na tog novog niza-pozadinca nit' možemo, nit' moramo referisati, osim ako ne pišemo nešto kao debugger. Obične smrtnike treba da boli uvo za nizove-pozadince. U stvari, dugo ćete po standardnim bibliotekama kopati da bi našli mesto gde se neko zeza sa pravim nizom, a ne slajsom. Normalno je kreirati slajs kad god vam zatreba nešto što liči na niz, a nizovima-pozadincima neka se bavi Go.

Primetimo sada nešto malkice čudnjikavo. Ako bi sada najednom odštampali `len(y)` i `cap(y)`, dobili bismo 11 i 20:
```go
    fmt.Println(len(y), cap(y))
```
```
    11 i 20
```
Au, bre, kako sad pa to? Dobro, 'ajde, razumemo da je `len(y)` sada 11. Na kraju krajeva, `len(y)` smo dobili tako što smo na slajs dužine 10 dodali još jedan element. Ali otkud sad ovo 20? :confused: 

Stvar je u tome što je izmišljanje novog mrše za drndanje jedna skupa operacija koja iziskuje kopiranje starih elemenata, pa Go pokušava da joj spusti cenu. Go razmišlja nekako ovako: *aha, sada mi treba mrša dužine 11, ali šta ako ovaj tenkre malo kasnije doda još nešto, pa mi zatreba 12? Hmmm... 'ajde zato da ja odmah sada, dok sam tu, sklepam mršu duplog kapaciteta u odnosu na onog starog, jer me to manje košta nego da svaki čas izmišljam novog kad god ova budala doda jedan element*.

Drugim rečima, Go na ovaj način nalazi dovoljan kapacitet za rad vaših slajseva eksponencijalnom brzinom, što je uglavnom zadovoljavajuće.

---

Jebote, toliko reči zbog jednog slajsa. Vreme je da se ide dalje:
```go
    func random() (string, error) {
        ...
    }    
```
Ovo prosto znači da `random()` ne prima nikakve parametre, a vraća string i grešku (error). Po veoma prihvaćenoj konvenciji među Gopherima, ako je error == nil, nema greške. Ovo je i somu jasno.

---

```go
    buf := make([]byte, tokenLength)
```
Ovde kreiramo slajs bajtova dužine `tokenLength`, koji će Go inicijalno uvek nafilovati nulama. 

Funkcija `make()` je specijalna funkcija standardne biblioteke koja zna da kreira samo 3 stvari: mape, kanale i slajsove. Ako bacimo pogled na njenu deklaraciju, naletećemo na ovo:
```go
    func make(t Type, size ...IntegerType) Type
```
Ovo znači da se prvi parametar ove funkcije referiše na željeni tip (za koji moramo biti sigurni da `make()` zna da ga napravi). Kod nas je to slajs bajtova(`[]byte`). Drugi (i eventualno treći) parametar govore o veličini toga što želimo da `make()` napravi. Luk i voda, zar ne?

Neko će sada reći: alo, bre, a zašto sada izmišljamo toplu vodu, a ne koristimo istu konstrukciju kao onda kada smo deklarisali promenljivu `tokenLetters`? I onda smo dobili nekakav slajs, zar ne?

Stvar je u tome što to sada nije praktično jer ne znamo unapred čime ćemo ovaj slajs puniti, a onda smo znali (`abcdefg......0123456789`). Sve što znamo je da `buf` želimo puniti nekakvim slučajnim brojevima, a ovo ni u ludilu ne može biti unapred.

---

O nizovima i slajsovima može još mnogo da se priča, ali vreme je da krenemo dalje. Prelazimo na sledeću liniju funkcije `random()`:
```go
	_, err := rand.Read(buf)
```
E ovu liniju valja zaliti, jer je ovo prva linija do sada koja stvarno nešto radi. :beer: 

Paket `crypto/rand` nam donosi funkciju `rand.Read()` koja ima sledeći potpis:
```go
    func Read(b []byte) (n int, err error)
```
Potpis nam govori da mi funkciji treba da pošaljemo nekakav slajs bajtova, a `rand.Read()` će da nagura u taj slajs slučajne bajtove od 0 do 255. Osim toga, funkcija nam vraća broj bajtova koje je ugurala u slajs, a i nekakav `error` koji sigurno neće biti `nil` ukoliko je došlo do nekakave greške. S'tim u vezi, zanimljiv je komentar autora funkcije `rand.Read()`, koji kaže: 

*On return, n == len(b) if and only if err == nil.* 

Ovaj komentar za nas ima praktično značenje jer nam je nacrtao crno na belo kako da koristimo funkciju. Kako izlazne vrednosti direktno zavise jedna od druge, ovo znači da nam ne trebaju obe, nego samo jedna od njih. Opredelili smo se da to bude `error`, jer nam broj bajtova nije interesantan. Jer ako do greške dođe, broj bajtova nas se neće ticati (delimično napunjen bafer ionako ne možemo da iskoristimo). A ako do greške ne dođe, tada će broj bajtova, sudeći po komentaru autora, ionako biti jednak dužini bafera. Primetite podvlačilicu sa leve strane naredbe dodeljivanja; njom dajemo signal da smo odlučili da prvu izlaznu vrednost funkcije ignorišemo. A što se tiče druge, nju želimo da je Go sačuva u promenljivoj koju smo krstili `err`.

Postoji još jedan principijelan razlog zbog kojeg smo se opredelili da ne ignorišemo grešku (`error`): **nikada ne ignorišite greške**! U suprotnom, to će vam se kad-tad obiti o glavu. Zamislite da smo recimo (pogrešno) zaključili da `rand.Read()` nikada neće vratiti grešku, te da smo kod napisali tako što smo ignorisali obe izlazne vrednosti:
```go
	_, _ = rand.Read(buf)
	for i := 0; i < tokenLength; i++ {
		...
	}
```
Naš bafer će svejedno biti napunjen... *most of the time*, ali ovo je totalno pogrešno. Prvo i prvo, pa valjda onaj ko je pisao `rand.Read()` zna bolje od nas da li ovde može ili ne može da dođe do greške. I ukoliko stvarno ne bi moglo, onda bi potpis njegove funkcije sigurno izgledao drugačije. Zato ako zaista odlučimo da ne ispoštujemo potpis, a do greške jednog dana ipak dođe, program će naizgled nastaviti da radi bez greške, samo što će nam se svi tokeni kod kojih se desila ova greška početi da se završavaju na **a**. U stvari, najveće su šanse da će svi tokeni postati jedno dugačko i tužno **aaaaa**.

---

Sada dolaze na red 3 linije koje su na prvi pogled proste kao pasulj, ali na kojoj ćemo se zadržati jer se ovde zaista radi o jako važnim stvarima. Radi se o proveri izlazne vrednosti `err`:
```go
	if err != nil {
		return "", err
	}
```
Kad smo bili šiljokurani, sećam se da su nas učili vrlinama nečega što se onda (a valjda i sada?) zvalo strukturno (ili strukturalno, jebemliga) programiranje. Sve nešto kao GOTO naredba ne valja, nešto o dobroti grananja `if`-ova i `else`-ova, a naročito to da `return` naredba treba da bude na kraju procedure, tako da se algoritam na izlasku iz svih onih silnih `if`-ova, `else`-ova i petlji prosto ulije u nju. U stvari, kad razmislim, učili su nas da pišemo kod koji je bio jednako težak za čitanje kao Krleža. Za ilustraciju koliko ovo može biti zajebano, naučio sam napamet jednu Krležinu rečenicu sa nekog njegovog gostovanja u studiju na televiziji. Čim je uzeo reč, rekao je nešto ovako:

> Posmatrajući to pitanje sa stanovišta moralno-političkih kompetencija, moram vam reći da stvar zrači vrlo fluidno i da nikakva insinuacija endogenih funkcija nije u mom domenu.

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

E sad: kako nešto što je 4 linije duže i jedan stepen uvlačenja teksta dublje može da bude bolje, a u stvari je isto? Čak i na ovako malom primeru, prvi listing podseća na onu Krležinu rečenicu gde je on u suštini hteo da kaže... eeer... ovaj... kašljuc.... dobro, ajde, nije baš da znam šta je hteo da kaže, ali u tome i jeste poenta.

Zato prihvatite kao prvu od 10 zapovesti programiranja da je palamuđenje o `return` naredbi opisano gore mlaćenje prazne slame. Nađite način da iz funkcije izađete što je moguće ranije, čim se za to steknu uslovi, i pobrinite se za to da se uslovi steknu što bliže početku funkcije, a što dalje kraju (na kraju funkcije treba da se izvršava kod predviđen za situaciju kada je sve bilo bez greške). I uvek učinite sve što je u vašoj moći da izbegnete `else`. Jer `else` je zlo, a bogami i naopako. 

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

Ovo što smo do sada rekli o greškama je primenljivo na sve programske jezike, ali, kada se radi o Go-u, uvek preferirajte stil koji se u jednoj rečenici može opisati kao *brigo moja, pređi na drugoga!* E to je upravo ono što smo uradili u ove tri linije koda :smile: Čim dođe do greške, odmah vrući kesten uvaljujemo onome ko nas je zvao, i zadovoljno peremo ruke. 
                                                                         
Međutim, nije sve baš tako prosto: *bar na jednom mestu* u vašem programu morate imati nekakvog sakupljača grešaka koji će sa njima nešto da radi. Jedan od najboljih kandidata za to mesto je `main()` u paketu `main`, a to su funkcija i paket koje morate imati ako želite da se vaš program izvrši (ako nigde nemate `main.main()`, vaš program nije program, nego biblioteka). E sad, šta sakupljač grešaka treba pametno sa njima da radi? Logovanje grešaka u fajl je dobra stvar. Ispis grešaka na ekran je takođe dobra stvar. A ako je greška suviše ozbiljna, nije zgoreg ponekad pozvati i `panic()`. Program će na ovaj način završiti u jarku pored puta, ali to je ponekad zaista najbolje, zar ne? 

###### Poređenje sa Javom

U Javi, greška se zove izuzetak (*exception*), a obrada grešaka - obrada izuzetaka (*exception handling*). Go nema obradu izuzetaka kao Java, čime se želi reći da nema nešto ni nalik na *try-catch-finally* - blokove iz Jave. Ipak, zapitajmo se: koliko su ovi blokovi bolji od onog što Go ima? 

Pogledajmo kako izgleda jedan tipičan *try-catch-finally* blok u Javi, a kako njegov ekvivalent u Go-u. Zamislite da imamo nekakvu funkciju `open()` koja vraća neki resurs koji na kraju balade treba zatvoriti, ali koji zna i da baci izuzetak ukoliko resurs zbog nečeg ne može da se napravi. U Javi, *try-catch-finally* blok za ovo tipično izgleda ovako: 

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
E sad, iako je Javina obrada izuzetaka po mnogima do jaja, čak i u ovom maleckom primeru možete naći čak četiri WTF-a:

1. Izuzeci se često obrađuju u blokovima koji su vizuelno daleko od mesta gde su nastali, pa morate stalno da upirete pogled gore-dole
2. Resursi se još češće zatvaraju u bloku koji je vizuelno daleko od mesta gde su nastali, što ume da dovede do zaborava (curenja memorije)
3. `finally` blok je slepac; on nema pojma da li je bilo izuzetka ili ne, pa mora jadan nešto ekstra da proverava
4. Cela konstrukcija deluje Krležijanski komplikovano, ali i nepotrebno dugačko

Ekvivalent ovog bloka u Go-u je daleko ekonomičniji. Go podstiče na to da se greške obrađuju što bliže mestu gde su nastale, a da brigu o zatvaranju resursa skinete squrca što bliže mestu gde je resurs nastao. Tako je lakše i Go-u i vama, što dovodi do boljeg koda:
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
 Primetite upotrebu naredbe `defer`. Ona je kao tempirana bomba koja se aktivira *neposredno pre nego što funkcija efektivno izvrši `return`*. Na ovaj način smo osigurali da će se `r.close()` kad-tad izvršiti, ali ne slepački, kao u Javinom finally-bloku. Jer, ako zbog greške resurs nikada ni ne bude otvoren, `defer` neće ni doći na red jer u tom slučaju neće imati šta ni da se zatvara.
 
Drugim rečima, 1:0 za Go na ovom mestu.

---

Od sada će disekcija funkcije `random()` ići brže, jer smo do sada dosta naučili:
```go
	for i, v := range buf {
		buf[i] = tokenLetters[v % byte(len(tokenLetters))]
	}
```

Ovako se u Go-u prolazi kroz niz (ili slajs) u petlji. U njoj će `range buf` vratiti indeks i vrednost svakog člana niza/slajsa. Ako nam neka od ove dve stvari ne treba, moguće ju je ignorisati korišćenjem podvlačilice (`_`).

U našem slučaju, slajs `buf` sadrži slučajne bajtove na koje ćemo se u petlji referisati preko promenljive `v`, a na njihov indeks preko brojača `i`. Ono što petlja ovde radi je to da ona svaki takav slučajan bajt zamenjuje slučajnim slovom iz slajsa `tokenLetters`. Rezultat je slučajni slajs sastavljen od takvih slova, a to je samo na korak od onog što nam treba. 

---

I evo ga taj korak: sledeća naredba vraća token, kao i `nil` umesto greške:

```go
	return string(buf), nil
```

Ovde se radi o konverziji jednog tipa u suštinski isti tip. 

Go definiše `string` kao *read-only* slajs sastavljen od bajtova (`[]byte`). Zbog bliskosti ova dva tipa, moguće ih je neposredno "izliti" iz jednog u drugi. Primetimo da smo obrnutu situaciju već imali kada smo inicijalizovali promenljivu `tokenLetters`:
```go
var tokenLetters = []byte("abc...789")
```

---

Krajnji je red je da se vratimo na implementaciju interfejsa `Store`, do ne zaboravimo šta smo ovde počeli.


###  Prvi pokušaj, a treći pitonizam: pa ovo mu ga dođe kao rečnik/mapa/yebemliga šta je!

Associjativni nizovi se u Pitonu zovu rečnici, u drugim jezicima mape, tabele *and what not*. Asocijativni nizovi su nizovi indeksirani nečim drugim, a ne samo uzastopnim prirodnim brojevima (u kom slučaju se kratko zovu nizovi). Oni postoje u svim programskim jezicima sveta, sa jednom bitnom razlikom. U jezicima poput Pitona i Go-a, asocijativne nizove "priznaje" kompajler, dok u većini drugih jezika kompajler o njima nema pojma, te su tamo asocijativni nizovi implementirani u okiru standardne biblioteke. 

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
 
Pošto interfejs `Store` veoma podseća na mapu, iskoristićemo ovu sličnost. Stvar je u tome što je u Go-u moguće "nalepiti" svaki interfejs na bilo koji tip. Iako Go nema klase, u Go-u apsolutno sve što postoji može implementirati bilo koji interfejs, i da se tako ponaša.

Ipak, interfejs `Store` ne možemo nalepiti na Go-ovu mapu `map[string]interface{}` direktno. Ovo je zato što mape pripadaju tuđem, a ne našem paketu, a Go zabranjuje lepljenje metoda na tipove koji nisu vaši. Ipak, ovaj problem skoro da ne postoji. Dovoljno je "usvojiti" ono što nam treba u naš paket, te, poput zle maćehe, pastorčetu raditi što nam je volja:

```go
type mapStore map[string]interface{}
```

Ovako se u Go-u poznatom tipu, koji je ovde mapa interfejsa indeksirana strngovima, daje novo ime. Primetite da ime novog tipa počinje malim slovom, čime želimo da kažemo da taj tip ne treba da bude vidljiv izvan našeg paketa. E sad, kako sad pa to? Kako mislimo da potrošači našeg paketa uopšte koriste `mapStore`, ako nisu u stanju ni da ga vide?
 
Pa tako što ćemo potrošačima našeg maketa eksponirati javni konstruktor koji im vraća instancu interfrejsa `Store`, krijući od njih implementaciju:

```go
func NewMapStore() Store {
	return mapStore(make(map[string]interface{}))
}
```
Ovde smo prosto konstruisali instancu mape koristeći funkciju `make()` (nju smo već koristili za slajsove), izlili mapu u naš novi tip i - voilà!

Ipak, kompajler će na ovom mestu početi da kmeči jer mu nije jasno zašto `mapStore` implementira interfejs `Store`. Uvalićemo mu cuclu dodavši metode:
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

Šta se ovde desilo?

Kao što vidimo, potpis novododatih funkcija se potpuno poklapa sa potpisom metoda iz interfejsa `Store`. Ali, za razliku od metoda iz `Store`, ovo više nisu pusta obećanja: ove funkcije imaju telo koje zaista nešto radi. Osim toga, ove funkcije nisu obične funkcije, kao recimo `random()`. Ove funkcije definišu **primaoca** (*receiver*), što se u našem slučaju svodi na promenljivu tipa `mapStore` koju smo ovde krstili `ms`:

```go
func (ms mapStore) Store...
func (ms mapStore) Fetch...
```

Upravo na ovom mestu u deklaraciji Go-ovih funkcija se na poznate tipove lepe interfejsi. Da bi kompajler shvatio tip `mapStore` kao `Store`, obe metode moraju da budu implementirane. Izbrišite bilo koju od njih, i kompajler će opet početi da kmeči.

Primetite kako se u Go-u koriste mape. Budući da je `mapStore` u suštini jedna mapa, kad god želimo nešto staviti u nju, koristimo pitonijansku sintaksu:

```go
    ms[token] = payload
```
Sintaksa je slična kao kod nizova, ali ovo je samo zbog toga što mape možemo shvatiti kao nizove indeksirani nečim drugim, a ne samo uzastopnim prirodnim brojevima.

Kod očitavanja iz mape, sintaksa je malkice drugačija nego u Pitonu: 

```go
    payload, ok := ms[token]
```
Kod očitavanja, Go vraća dve vrednosti. Prva je vrednost koju tražimo, a druga je `bool` koji nam govori o tome da li je vrednost pronađena u mapi ili ne. Ovu drugu vrednost potrebno je uvek proveriti, što smo gore i učinili.

U Javi, kompajler ne poznaje čitanje iz mape, pa to činite pozivima biblioteke:

```go
    v = m.get(key)
```

U slučaju da ključ `key` nije u mapi, `m.get(key)` će vratiti `null`. Međutim, ako ključ `key` jeste u mapi, ali tamo, eto, ima vrednost baš `null`, opet će vam `m.get(key)` vratiti `null`. Drugim rečima, U Javi, ove dve situacije prostim čitanjem nije moguće razlikovati. Zato, ako nam treba razlika, u pomoć moramo prizvati metodu `m.containsKey()`, što znači da ćemo u tom slučaju mapu prozivati (skanirati) čitava 2 puta: jednom da bi saznali da li mapa sadrži vrednost, i još jednom da bi očitali vrednost. Ovo je još jedna rogobatnost koja se može pripisati nemoći Jave da vrati više vrednosti odjednom. U Go-u, zauzvrat, ovo je elegantno rešeno u jednom koraku, kao što vidimo gore.

Na kraju, sa stanovišta klijenta, ovako se kod konzumira ono što smo do sada napisali:

```go
    store := token.NewMapStore()
    token, err := store.Store("neki qrac")
    if err != nil {
    	panic(err)
    }
    payload, err := store.fetch(token)
    if err != nil {
    	panic(err)
    }
    fmt.Println(token, payload)
```

Napomena: funkcija `panic()` se uglavnom koristi u primerima. U pravim programima, *samo πčke paniče*. A ako se ipak uspaničite, potrudite se da negde napravite `recover`, jer u suprotnom vaš će program odvaliti nosom o ledinu.


###### Unit testovi u Go-u

Ekstra je super kad programiranje prema interfejsima podseća na pisanje pozorišnog komada, pri čemu je programer ujedno i pisac i reditelj. Interfejsi su **lica** u komadu, a metode su njihove **replike** koje glumci moraju da nauče. **Glumci** su implementacije interfejsa; nekima ćete biti više, nekima manje zadovoljni, ali je važno da se, bez obzira kojim ste glumcima podelili uloge, odvija isti komad. Svi drugi tipovi i funkcije koje nisu ni interfejsi ni njihove implementacije su **rekviziti**, kao recimo naša funkcija `random()`. Ona liči na pištolj na stolu koji izađe na videlo čim se podigne zavesa, a za kojeg znate da će kad-tad u toku predstave da opali. 

E sad, šta su unit-testovi? Unit teastovi su **audicija** za glumce; ulogu nećete dati glumcima koji ne prođu audiciju, zar ne? Vrlo je važno da implementacije vaših interfejsa podvrgnete nekakvim izazovima, da bi proverili da li su oni zaista naučili svoju ulogu, kao i to da li je igraju na najbolji mogući način. U praksi, kôd nekog programa često menjate i ispravljate, pa su vam unit-testovi neka vrsta sigurnosne mreže, ili provera da li su vaše poslednje izmene nešto pokvarile.

Za osveženje, Go "priznaje" unit-testove na nivou kompajlera: naredba `go test -v` će izvršiti sve unit testove nađene u direktorijumu (to jest paketu) u kojem se trenutno nalazite, i proizvesti nekakav output. E sad, ostaje pitanje: a šta je to što Go smatra unit-testom?

Za Go, unit-testovi su **funkcije** koje se vrzmaju po fajlovima imenovanim po mustri `*_test.go`. Osim toga, imena takvih funkcija moraju početi rečju `Test` (primetite veliko slovo), i te funkcije moraju primati tačno jedan parametar koji mora biti tipa `*testing.T`. Na primer:

```go
import "testing"

func TestSomething(t *testing.T) {...} 
```

Paket `testing` je *built-in* paket koji nam pomaže kod testiranja. Da ne bi mnogo palamudili, napiåimo øaskom neåto. Lice imamo (`Store`), glumca imamo (`mapStore`), napišimo onda kratak unit-test u fajlu `token/mapstore_test.go` kojim ćemo ovog glumca podvrgnuti nekakvom izazovu:
```go
// ./token/mapstore_test.go
package token

import (
	"testing"
)

const samplePayload = "something"
const notAToken = "notAToken"
func testStoreFetch(t *testing.T, store Store) {

	token, err := store.Store(samplePayload)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := store.Fetch(token)
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

Ako bismo sada skoknuli do direktorijuma `token` i izvršili unit-test, dobili bi sledeći output:
```shell
    $ go test -v
    === RUN   TestMapStoreFetch
    --- PASS: TestMapStoreFetch (0.00s)
    PASS
    ok  	github.com/aboutgo/token	0.005s
```

Sada ćemo namerno da nešto malkice pokvarimo u implementaciji `mapStore`, da bi videli kako unit-test čumi bagove kao čuma decu. Izbrišimo sve u u `mapStore.Store()`, i napravimo izmeničicu koja uvek vraća isti token, bez sačuvavanja:

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
    FAIL	github.com/aboutgo/token	0.005s
```

---

Iako `mapStore` na prvi pogled izgleda bezgrešno, budući smo prinuđeni da mu namerno ušpricavamo grešan kod da bi demonstrirali kako `go test` otkriva bagove, ovo uopšte nije tačno. Sa samo nekoliko linija koda moguće je napisati unit-test koji će `mapStore` nemilosrdno nokautirati. Dodajmo sledeći test na već postojeći:

```go
func TestMapStoreFails(t *testing.T) {
	for i := 0; i < 100; i++ {
		go testStoreFetch(t, store)
	}
	time.Sleep(100 * time.Millisecond)
}
```

Sada ako izvršimo ove testove, dobijamo nešto ovako:

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
    FAIL	github.com/aboutgo/token	0.030s    
```

Drugim rečima, tečki pičvajz. Za red veličine gori nego onaj od malopre, namerni. 

Problem je u tome što `mapStore` nije *thread-safe*. Zamislite barmena u nekom baru koji, čim mu neki gost poviče "pivo", a on odmah, kao robot, slepo stavlja novu kriglu na punjenje, ne vodeći pri tom računa da li se tamo već nalazi neka druga krigla koja je već na punjenju. Na podu će neminovno biti mnogo razbijenog stakla, zar ne?

Posmatrajmo naredbu 
```go
    go testStoreFetch(t, store)
```
Ona se izvršava u petlji tačno 100 puta. Svaki put kada se ona izvrši, `Go` lansira novu nit (*thread*) u kojoj se izvršava funkcija `testStoreFetch`. Međutim, odmah zatim, ne čekajući da se prva nit završi, lansira se još jedna ista takva nit, pa još jedna, pa još jedna... i tako 100 puta. Na kraju petlje će biti kao da smo pustili roj od 100 niti od kojih svaka izvršava jednu te istu funkciju u nekakvom isprepletanom kompjuterskom vrememnu. Ovo je tazlog što na kraju petlje čekamo jednu desetinku sekunde, da nitima iz roja damo dovoljno vremena da naprave karambol.

Stvar je u tome što je mapa jedna, a niti ima 100 komada. I taman kada jedna nit počne u nju nešto da piše, ta nit biva na pola posla prekinuta novom niti koja isto tako pokušava da tamo nešto piše. Ovo rezultuje u *fatal error: concurrent map writes*, što izveštaj našeg unit-testa potvrđuje.

U Javi, ovo se trivijalno rešava tako što tamo postoji nešto što se zove `ConcurrentMap`, to jest mapa koja obećava da je *thread-safe*. *Thread-safe* znači da mapa implementira nešto nalik na semafor: samo jedna nit biva puštena da uđe u "kritičnu zonu", dok sve ostale čekaju na crveno dok ona prva ne obavi svoj posao i izađe. E sad: u Go-u, koliko je meni poznato, osim kanala (*channels*) nema ništa što je samo po sebi *thread-safe*. Međutim, jezičke konstrukcije namenjene paralelnom programiranju u Go-u su toliko jasne i razgovetne da se ja lično, bar što se paralelnog programiranja tiče, mnogo komfornije osećam u Go-u nakon samo mesec dana iskustva nego što sam se ikada osećao u Javi.

###  Drugi pokušaj: `SyncedMapStore`

Jednu konstrukciju paralelnog programiranja u Go-u smo već videli: to je naredba `go` po kojoj je programski jezik Go dobio ime. Ona lansira novu nit (*thread*) koja izvršava zadatu funkciju (u našem slučaju `testStoreFetch()`). Ovako puštene niti se u Go-u zovu go-rutine (*goroutines*). Za sada, one se ponašaju kao pušteni baloni napunjeni helijumom: na njih isto tako nemamo nikakav uticaj niti kontrolu. Kasnije ćemo videti da je i njih moguće podvrći kontroli, ali o tome kasnije.

Nama trenutno treba način da sinhronizujemo pristup mapi `mapStore`. U tu svrhu služi `sync.Mutex` iz paketa `sync`. Na primer, ovim deklarišemo promenljivu tipa `sync.Mutex`

```go
    import "sync"

    var mu sync.Mutex
```

Sada je jednostavno. Na ulasku u zonu koju štitite pozovete `mu.Lock()`, na izlasku - `mu.Unlock()`. Ako neka nit naiđe na `mu.Lock()` u momentu kada je pre nje neka druga nit već prošla muteks, ona će čekati "na crveno" da ta druga nit napravi `mu.Unlock()`. Ako ima mnogo niti, ispred muteksa zna da se ponekad napravi kolona, ali će Go puštati kroz mutex jednu po jednu, kao panduri kad na autoputu sa više traka nešto pregrade, tako da saobraćaj sliju u samo jednu traku, puštajući vozila u koloni jedno po jedno.

Problemčić je što naš `mapStore` nema mesta za jedan takav muteks. Doduše... budući da mapa može da primi sve što je kompatibilno sa `interface{}`, ona bi mogla i da proguta muteks pod nekim konstantnim ključem, na primer. Ali problem time ne bi nestao. Da bi se došlo do muteksa sačuvanog u mapi, moramo *čitati* iz mape, a to je upravo ono što pokušavamo da sinhronizujemo. 

U Go-u, za ovaj posao služe strukture. One su mnogo sličnije strukturama u C-u nego klasama u Javi, s' tom razlikom što strukture u Go-u mogu imati metode. Stari kod napisan za potrebe `mapStore` nećemo ni bacati, niti menjati, nego ćemo ga prosto ponovo iskoristiti. Ne zato što je tako jednostavnije (u stvari, nije), nego da bi pokazali jednu od tehnika pomoću koje je moguće postiću efekat nasleđivanja iz jezika koji poznaju klase.

###### Strukture u Go-u

U novom fajlu (`token/syncedMapStore.go`) definisaćemo sledeću strukturu:

```go
type syncedMapStore struct {
	mapstore mapStore
	mu       sync.Mutex
}
```

Naravno, struktura počinje malim slovom jer ne želimo da ona bude vidljiva van našeg paketa. Odmah napišimo konstruktor (obična funkcija u Go-u koju zovemo konstruktor; nemojte misliti da Go stvarno ima nešto što se zove konstruktor) koji vraća interfejs iza kojeg stoji ova struktura:

```go
func NewSyncedMapStore() Store {
	return &syncedMapStore{mapstore: mapStore{}}
}
```
Primetimo ampersend (`&`) ispred strukture koju vraćamo. Malo strpljenja, stvar će se razjasniti kad vidimo kako smo implementirali metode. Za sada recimo samo to da taj znak služi da zadovoljimo kompajler.

U stvari, ispada da ga ipak nismo potpuno zadovoljili: kompajler i dalje kmeči! Ovo zato što nešto ne vidi da `syncedMapStore` implemetira `Store`. Stvarno, kako da vrati nešto što treba da prođe kao `Store`, kad mu fale metode?

Ništa zato, dodajmo metode. Primetite upotrebu naredbe `defer`. Ona osigurava da se mutex neizostavno otključa neposredno pre izlaza iz metode:

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
Budući da je sada kompajler prestao da kuka, prepravimo unit-test od ranije, te provucimo `syncedMapStore` kroz njega:

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
    ok  	github.com/aboutgo/token	0.108s
```

---

Ostaje da se vidi šta će nam onaj ampersend u konstruktoru (`&`), a naročito šta će nam one zvezdice kod primalaca (`*`)?

Ovo ima veze sa prenosom parametara u Go-u: *oni se uvek prenose po vrednosti*. E sad: stvar je u tome što Go priznaje vrednosti koje znači pointer na nešto drugo, na koji način se postiže nešto što liči na prenos po referenci. Primetimo da ovo isto važi i za primaoce metoda (*receivers*): u vremenu izvršenja, primaoci nisu ništa drugo nego prvi parametar svojih metoda. U ovom slučaju, na primer, metoda `func (sms *syncedMapStore) Store(payload interface{})` se u vremenu izvršenja transformiše u običnu funkciju čiji je prvi parametar pointer na `syncedMapStore`:

```go
    func Store(sms *syncedMapStore, payload interface{})
```

Znak `*` u potpisu znači da metodi `Store` želimo isporučiti pointer na `syncedMapStore`, a ne goli `syncedMapStore` (što bi bilo prenošenje po vrednosti). Ostaje da se odgovori zašto, ali prvo primetimo da se promenljive tipa "pointer na nešto" deklarišu kao u C-u, pomoću `*`. Na isti način, znak `&` se koristi da se izvuče pointer na nešto što se već nalazi u nekoj promenljivoj, baš kao u C-u.

E sad: šta će nam ovde uopšte pointeri?

Mi smo mogli, da smo hteli, napraviti ne-pointersku verziju `syncedMapStore`-a, ali time ne bismo rešili naš problem:
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

Kad god Go prenosi neki parametar u funkciju, on to čini po vrednosti. To znači da će Go uvek napraviti kopiju vrednosti koju prenosite. A ako ne želite kopiju, postarajte se da prenesete pointer. I pointer će u krajnjoj konsekvenci biti prenet po vrednosti, ali će bar pokazivati na istu stvar, zar ne?

Podsetimo se, naša struktura izgleda ovako:
```go
type syncedMapStore struct {
	mapstore mapStore
	mu       sync.Mutex
}
```

Svaka kopija te strukture sadržaće kopiju od `mapstore` i kopiju muteksa `mu`. Međutim, mape u Go-u, poput slajsova i kanala, su na neki način **već pointeri**: svaka kopija neke mape pokazuje na isti segment u memoriji gde original čuva svoje podatke. E sad, to što važi za mape (slajsove i kanale), ne važi ni za šta drugo, uključujući tu i mutekse. To znači da kopije strukture `syncedMapStore` sadrže suštinski istu mapu `mapstore`, ali različit muteks. Go-rutine će zato zaključavati i otključavati svoje privatne kopije muteksa bez problema, ali će i dalje nastaviti da se kolju oko iste mape. Otuda greška.

Stvar možemo popraviti a da pri tome ipak zadržimo ne-pointersku pririodu najnovije verzije `syncedMapStore`. Ipak, *na nekom mestu* moramo u priču uključiti pointere, jer se moramo postarati da čak i kopije strukture `syncedMapStore` sadrže isti muteks. Ovog puta deklarisaćemo sam muteks kao pointer, inicijalizijući ga u konstruktoru:

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

Primetimo da će i u ovom slučaju dolaziti do kopiranja `syncedMapStore`-a kad god pozovemo neku od njenih metoda, ali će kopije sadržati pointere koji pokazuju na istu stvar. Zato je pointerka implementacija cele stvari možda ipak čistija. Ako ništa, kopiranje košta nešto, a brže je kopirati jedan pointer nego dva, zar ne? :smile: 

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
Vreme ispod jedne sekunde uopšte nije loše za sabiranje tolike količine brojeva, ali recimo da nam je i to presporo, i da želimo da to skratimo. Ako bi podelili posao na 3 poziva funkcije `sum` tako da svaki poziv sabira svoj blok od milijardu brojeva, učinili bismo još gore ukoliko bi se to dešavalu u istoj niti/*thread*-u:
```go
	start := time.Now()
	s := sum(0*1000*1000*1000 + 1, 1*1000*1000*1000) 
	s += sum(1*1000*1000*1000 + 1, 2*1000*1000*1000) 
	s += sum(2*1000*1000*1000 + 1, 3*1000*1000*1000) 
	elapsed := time.Since(start)
	fmt.Println(s, elapsed) // štampa 4500000001500000000 912.923119ms
```
```
    štampa 4500000001500000000 912.923119ms
```

Ipak, na pravom smo putu. Najbolje je da ova tri poziva pokrenemo kao 3 paralelne go-rutine koje bi se izvršavale istovremeno. Ukupno vreme rada će ostati isto, ali, zbog paralelizma, vreme čekanja na rezultat biće svedeno otprilike na trećinu. Trojica radnika iskopaju kanal za trećinu vremena nego što bi to uradio jedan radnik, zar ne?

Međutim naša funkcija `sum()`, takva kakva je, potpuno je nepogodna za tako nešto. Ona vraća rezultat kao izlaznu vrednost, i tu vrednost je sposobna da vrati samo pozivaču iz iste niti u kojoj je i ona sama. Mi i dalje možemo postići da se pozivi `sum()`-a izvršavaju u paralelnim nitima, ali ti pozivi bi se ponašali kao 3 balona napunjena helijumom. Jednom pušteni, oni ne bi imali nikakvu komunikaciju sa zemljom, niti bi ih mi mogli na ikoji način kontrolisati.

Probajmo nešto skroz blesavo. Go dopušta bezimene (unutrašnje) funkcije koje možete izvući "kano ljutu guju iz njedara" (*closures*), a koje imaju direktan pristup lokalnim promenljivima deklarisanim u glavnoj niti. Ako bi lansirali jednu takvu funkciju 3 puta, interesantno je pitanje kakav će biti rezultat:

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
Anonimna funkcija koju držimo u promenljivoj `suma` dodaje brojeve onako kako joj nailaze direktno na `s`. Osim toga, ona inkrementira `doneCounter` čim završi veliko sabiranje. Glavna nit čeka da sve tri go-rutine završe posao u petlji, ispitujući promenljivu `doneCounter`, i tek onda štampa rezultat. 

Ipak, rezultat koda gore je njesra:

```
    1557301230835831450 2.169120056s
```

Iako se ništa nije zaglavilo, jer je u Go-u sabiranje celobrojnih vrednosti očigledno atomska operacija koja se ne može se usred posla prekinuti, ovaj rezultat, kao prvo, uopšte nije tačan. Stvarno, kako to da smo na promenljivu `s` očigledno dodali svih 3 milijarde brojeva koje smo trebali dodati, a ipak dobili netačan rezultat?

Stvar je u tome što se naredba `s += i` koju izvršava funkcija `suma` sastoji od bar dve različite operacije: 1. `očitavanje starog s-a` 2. `upis novog (inkrementiranog) s-a`. Svaka od tih operacija jeste atomska, ali one zajedno u nizu to nisu: u prostoru *između njih* postoji opasnost da se ušunja neka druga nit/*thread* i da zajebe stvar. Svaki put kada se to desi (a u ovom slučaju desiće se mnogo puta, zato što je veliki broj sabiranja sabijen u jednu tačku prostora i vremena), sabiranje prosto "prezupči". Na primer, zamislite da nit A očita promenljivu `s` koju nit B samo što nije promenila. Za vreme dok nit A računa izraz `s + i`, nit B je već promenila `s`, tako da, kad nit A upiše novo `s`, ona će da prejaše plodove rada niti B. Na ovaj način, mnogi od sabiraka bivaju progutani, što je razlog da nam konačna suma nije tačna.

Osim toga, u kodu gore ima jedan veeeeeliki bag. Sve što smo rekli za `s` važi i za `doneCounter`, tako da smo prosto imali sreće da `doneCounter` nije prezupčio na isti način kao `s`. Da se to desilo, uzaludno bi čekali da se ove 3 go-rutine završe. U stvari, one bi se jadne još i završile, samo mi to ne bismo znali. Zato nikada ne inkrementirajte brojeve na ovaj način. Koristite `doneCounter++`, što je u Go-u atomska operacija.

Novo vreme izvršavanja koje smo dobili gore je katastrofa. Ovo je zato što sada niti (*thread*-ovi) čekaju čak na dva semafora kod operacija 1. i 2, te se niti provlače kroz kod kao kroz vrzinu. 

Korektnost rezultata možemo popraviti tako što ćemo "atomizirati" operacije 1. i 2, ali nemojte ni pokušati ovo da izvršite, toliko je sporo:
```go
    mu.Lock()
    s += i
    mu.Unlock()
```

---

U pomoć nam dolaze kanali (`chan`). Kanal u Go-u je kao nekakav voki-toki kojim možemo da snabdemo go-rutine pre poletanja, a pomoću kojeg nam one javljaju šta se kod njih dešava:
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
Rezultat, osim što na njega čekamo mnogo kraće, je uz to i tačan. Istina, vreme izvršavanja nije svedeno baš na trećinu, ali tu je negde. 

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
Primetite smer strelice. Ona uvek pokazuje s' desna na levo. Ali ako pokazuje prema kanalu, u kanal se nešto gura. Ako je obrnuto, iz kanala se nešto vuče/čita. Nakon što je lansirala 3 go-rutine, glavna nit čita iz kanala tačno 3 puta, dobivši konačan rezultat prostim sabiranjem:
```go
    s := <-ch
    s += <-ch
    s += <-ch
```
I to je to. Jednostavno, čisto, bez gužve. Ovaj idiom je toliko sladak da nije čudo što Go postaje sve popularniji, a neki ga zovu i jezikom budućnosti.

---

Ipak, nemojte nikad na ovaj način čitati iz kanala, osim u situacijama kada ste sigurni da će vaša go-rutina da završi posao u prihvatljivom roku. Čitanje iz kanala je *blokirajuće*, što znači da će vaš program ovde da stane i da čeka sve dok se tamo ne pojavi neka vrednost. E sad: a šta ako se tamo nikada ne pojavi neka vrednost? Ili ako je vreme čekanja na tu vrednost neprihvatljivo? Takve slučajeve ćemo doživeti kao da se program zaglavio, a to valja izbeći, zar ne?

Snabdene voki-tokijem ili ne, go-rutine, jednom lansirane, ponašaju se kao pušteni baloni nad kojima u opštem slučaju nemamo kontrolu. Iako je moguće uz nešto grčenja isprogramirati nekakvu kontrolu, ipak je najčistije pobrinuti se da se go-rutine kad-tad završe, a za komunikaciju sa njima koristiti kanale. Isto tako, uvek dajte svojim go-rutinama rok u kojima bi trebalo da završe svoj posao. Ovo se u Go-u lako implementira korišćenjem naredbe `select`, jedne prelepe jezičke konstrukcije motivisane upravo potrebama paralelnog programiranja.

---

Da bi ilustrovali poentu, učinićemo našu funkciju `suma` namerno nestašnom, da bi je kasnije ukrotili. Recimo da funkcija na početku sa verovatnoćom 0.25 odlučuje da li da spava jednu čitavu sekundu ili ne. Ovako simuliramo nepredvidljivost vremena izvršavanja. U realnom životu, ova nepredvidljivost može nastati zbog nekog upita upućenoj nekoj preopterećenoj bazi podataka, ili zbog nekog pičvajza na mreži, nebitno:

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

Verovatnoća da će bar neka rutina da spava je ovde 55/64, što je dosta veliko da uz samo par pokušaja naletimo na ovu situaciju. Kada se to desi, rezultat izgleda ovako:

```
    4500000001500000000 1.297851977s
```

E sad, zamislimo sada da našim go-rutinama želimo dati samo jednu sekundu za završe čitav posao. A ako ga ne završe, želimo da glavni program liže svoje rane smatrajući da nema nikakav rezultat. Za ovaj scenario može poslužiti prelepa kontrukcija `select`. Ova konstrukcija je veoma razgovetna baš zato što je misaono rekurzivna: stvar se opet svodi - na čitanje sa kanala!

Spakovaćemo sakupljanje pod-rezultata u jednu posebnu funkciju kojoj ćemo dati kanal kroz koji će nam ona vratiti ceo rezultat: 

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

Sada ćemo kreirati kanal kojoj ćemo predati go-rutini `wait`, a u `select`-u čekati na dva kanala, pa šta prvo naleti:

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

Naredba `select` služe za čekanje na jedan ili više zadatih kanala, pa šta prvo naiđe. I ova naredba je blokirajuća, ali, šta god da naiđe na nekom od kanala, program će izaći iz `select`-a i nastaviti sa radom. Ovde nam u pomoć priskače paket `time` koji nudi veoma zgodnu funkciju `After()`, dušu dala za tajmere. Ona nam vraća kanal u koji će sigurno nešto da upiše nakon vremena koje smo mi zadali. Tako ako se nešto pojavi prvo na **tom** kanalu, smatraćemo da se desio kuršlus i da konačan rezultat nemamo. U suprotnom, rezultat je tu, i sve što preostaje učiniti jeste odštampati ga.

---

E sad: u slučaju da se desi tajmout, kakva je sudbina one četiri go-rutine koje smo lansirali?

Sudeći po tome kako smo ih napisali, one će jednom sigurno završiti svoj posao, samo neće imati kome da predaju rezultat: mi tada više nećemo biti tu. Drugim rečima, mi na njih u tom slučaju zaboravljamo. Zato je bitno pisati go-rutine tako da one što pre završe započeti posao čak i onda kada na njih zaboravimo. Ponekad ih je potrebno dodatno cimnuti za rukav, signalizirajući im da prekinu to što rade šta god da rade. Jer, ako ništa od ovoga ne uradimo, nakupiće nam se đubre od nezavršenih go-rutina koje, osim što žderu memoriju, troše i CPU.

___
___
---

Na ovom mestu sam na početku mislio da završim ovo pisanije, ali mi savest nekoga ko se profesionalno bavi softverom ne da mira. Stvar je u tome što `syncedMapStore` nije ni za qrac. Dobro, u redu je ponekad skratiti pisanje nekog komada softvera ako mu, bar pod nekim uslovima, vidite upotrebnu vrednost. Stvar je u tome što bi taj uslov u ovom slučaju bio nenormalan, i glasio bi: `syncedMapStore` možete koristiti, ali samo pod uslovom da s' vremena na vreme restartujete program!

A ovo je, naravno :scream:

Problem je u tome što se u pravim garderobama često dešava da neki lik ili likuša preda neko njesra na čuvanje, a onda se na to popišmani i nikada se ne pojavi da to preuzme. Možda zato što je lik zaboravan, ili mu to nije dovoljno vredno. Nebitno, garderoba mora da ima način da uradi nešto sa stvarima koje tamo rakolje nenormalno dugo. U suprotnom, tamo bi se godinama nakupilo toliko đubreta da bi na kraju garderoba postala prenatrpana glupostima koje više nikome ne trebaju.

Sa garderobom ovo je još i kako-tako, ali šta ako se vaš `Store` koristi za čuvanje kukija na nekom serveru, gde ih em možete imati na milione, em im morate davati nekakav rok trajanja? Zato...

###  Treći (i za sada poslednji) pokušaj: `TokenStore`

Sve u svemu, valja u priču uvesti TTL (*Time To Live*), ali kako? 

Na prvi pogled, to ne izgleda naročito teško, ali ovo je ipak nešto teže nego što to na prvi pogled izgleda. Podsetimo se prvo šta trenutno imamo na raspolaganju od implementacije:
```go
type syncedMapStore struct {
	mapstore mapStore
	mu       *sync.Mutex
}
```

Hmm, baš mršavo. Kao prvo, ovaj muteks nam ovde ništa ne pomaže, jer on ne donosi ništa funkcionalno novo. Doduše, tu je `mapStore`, a to već možemo iskoristiti.

Budući da `mapStore` može da primi svašta nešto, mami ideja da `payload`-ove pakujemo u koverte na kojima možemo naškrabati vreme nastanka i rok trajanja. Svaki put kad klijent zatraži `Store`, mi u `mapStore` sačuvamo ovako obeleženi koverat. A kada kasnije naiđe `Fetch`, mi sa koverte pročitamo da li `payload` još važi, te shodno tome vratimo rezultat:
```go
type envelope struct {
 	payload interface{}
 	created time.Time
 	ttl time.Duration
}
```

Da bi se što manje zezali, na `*envelope` odmah lepimo metodu koja nam vraća da li ovaj
payload još važi ili ne. 
```go
func (e *envelope) expired() bool {
	return e.created.Add(e.ttl).Before(time.Now())
}
```

Naša nova implementacija interfejsa `Store` se zove `TokenStore`. Ona proširuje postojeću strukturu `syncedMapStore`, a uz to i definiše TTL: 
```go
type TokenStore struct {
	syncedMapStore
	ttl time.Duration
}
```

Primetimo jednu jako interesantnu stvar. Ako i sada, kao ranije, časkom napišemo odgovarajući konstruktor za `TokenStore`, komapjler više ne kmeči. Zašto?
```go
func NewTokenStore(ttl time.Duration) Store {
	mu := sync.Mutex{}
	syncedMapStore := syncedMapStore{mapStore{}, &mu}
	return &TokenStore{syncedMapStore, ttl}
}
```

To je zato što `TokenStore` već implementira `Store`. Ovo nije lako odmah videti, ali u Go-u, ako strukturu koja implementira neki interfejs ugnezdite na ovaj način u neku drugu strukturu, onda se toj novoj strukturi priznaje da implementira isti interfejs.

Ipak, mi ovde moramo prejahati obe metode, zbog potrebe pakovanja i raspakivanja koverti koju nismo imali ranije:

```go
func (mem *TokenStore) Store(payload interface{}) (string, error) {
	envelope := envelope{payload, time.Now(), mem.ttl}
	return mem.syncedMapStore.Store(&envelope)
}

func (mem *TokenStore) Fetch(token string) (interface{}, error) {
	envelopeProbe, err := mem.syncedMapStore.Fetch(token)
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
Ovim smo dali tokenima novu funkcionalnost, rok trajanja, ali ovim se priča ne završava. Izjanđale tokene valja čistiti, ali kako?

---


###  Kuda dalje?

Ovim smo završili ono što smo ovde za sada nameravali implementirati, ali šta dalje? Drugim rečima, šta nam to još fali, a moglo bi zatrebati? Ako čitalac ima vremena i volje, mogao bi da proba nešto od toga i sam da implementira. Svaki *Pull Request* ću rado pregledati, i, ako je dovoljno dobar, prihvatiti u ovaj repo.

##### Različiti TTL-ovi

Ma koliko efikasan ovaj algoritam naizgled bio, upada u oči da on potpuno zavisi od toga da je TTL svih tokena uvek isti. Ali šta ako želimo da neke tokene sačuvamo sa jednim TTL-om, a neke druge sa nekim drugim? Drugim rečima, šta ako želimo implementaciju interfjesa koji proširuje interfejs `Store` na sledeći način:

```go
    type StoreWithTTL interface {
    	Store
    	func StoreWithTTL(payload interface, ttl time.Duration) (token string, err error)
    }
```

Na ovaj način, `StoreWithTTL` bi se i dalje ponašao kao `Store` sa standardnim TTL-om kad god zovemo stare metode, ali bi imao funkciju koja zadaje TTL koji moguće nije standardan.

---

Ovo ne bi trebalo biti mnogo teško, a ipak zadržati efikasnost algoritma iz `TokenStore`. Kao prvo, koliko različitih TTL-ova ćemo ikada imati? U praksi, obično se barata sa samo nekoliko različitih vrednosti TTL-a: super kratki (nekoliko sekundi), malkice duži (nekoliko minuta), još duži (nekoliko sati), pa onda nekoliko dana, nedelja, meseci i tako dalje. U svakom slučaju, teško je zamislivo da ćemo ikada baratati sa TTL-ovima čije se vrednosti prostiru na više od, lupam, par stotina različitih. Ovo znači da i dalje možemo tokene držati u jednoj mapi, ali da umesto jednog `tokenRing`-a možemo imati mapu `tokenRing`-ova za različite TTL-ove:

```go
    var tokenRingMap map[time.Duration]*tokenRing
```
 
Fabriku tokenRingova bi valjalo prepraviti da bude ttl-*aware*, i uz malkice još nekih prepravki, to bi trebalo biti to.

##### Distribuirani TokenStore

Ako vaš *host* čini više različitih mašina koje rakolje iza nekakvog *load balancer*-a, neophodno je da sve mašine imaju istu kopiju `TokenStore`-a, da bi stvar radila.

U tu svrhu, bilo bi zgodno da `TokenStore` hostuje nekakav HTTP (REST?) end-point kojim može da primi tokene koje su `TokenStore`-ovi sa drugih mašina kreirali, kao i to da može publikovati tokene koje je sam kreirao. Uz to, bilo bi zgodno da se `TokenStore`-ovi sami pronalaze na mreži, bez ikakve konfiguracije, a i to da, čim se neka nova mašina pojavi, da ima načina da od starih mašina primi sve tokene koji su trenutno važeći.

Ovde treba voditi računa o tipu podataka, jer payload-ove sa različitih mašina valja serijalizovati/deserijalizovati preko mreže. Json?

##### Perzistentni TokenStore

Iako nije sasvim obavezno, mašine se ponekad moraju restartovati/rekreirati, tako da bi isto tako bilo zgodno da TokenStore ima načina da u nekom intervalu serijalizuje svoj sadržaj u neku perzistentnu memoriju (recimo disk, mada i ovo treba biti konfigurabilno), tako da nove mašine mogu da se inicijalizuju recimo odatle. 






