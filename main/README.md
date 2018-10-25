# Upustvance za izgradnju

Ovaj paket, kada se izvrši, pokreće HTTP serverčić za igranje sa bibliotekom `token`.

Upustvance pretpostavlja da imate Go instaliran na vašoj mašini. Ako nemate, postupite prema uputstvu ovde: https://golang.org/doc/install

Ne znam kako ovo dalje ide na Windows-u (mora da je prosto), ali ako imate Linux ili Mac:

- Pozicionirajte se na ovaj direktorijum u komandnoj liniji i kucajte:

```shell
    $ cd ~go/src/github.com/aboutgo/main
    $ go build -o tokenplayground
```

U direktorijumu će se pojaviti izvršni program koji se zove `tokenplayground`. 

- Pokrenite program u background procesu:

```shell
    $ tokenplayground &
    [1] 51784
```

- Koristite komandu `curl` da se igrate.
    - Kreira novi token
        ```shell
            $ curl -X PUT localhost:8080?payload=AloBre`
            kNY5n7
        ```
    - Donosi sačuvano 
        ```shell
            $ curl -X GET localhost:8080?token=kNY5n7
            AloBre
        ```
    - Izlista ono što smo do sada sačuvali:
         ```shell
            $ curl -X GET localhost:8080/list
            mxz6J5          [ttl:    7459ms]: IdiBegaj
            CfTNrn *expired [ttl:  -10061ms]: AloBre
            GbYXj1 *expired [ttl:   -5757ms]: Proba
        ```

- Kad završite, koknite program `tokenplayground`
```shell
    $ killall tokenplayground
```


