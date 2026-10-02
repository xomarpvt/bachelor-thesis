# BotScope: risorse, artefatti e risultati

> *Tesi di Laurea in Informatica*\
> **Generazione agentica di moduli per la cattura dei comandi delle botnet**
>
> **Autore:** Omar Paviotti\
> **Relatore:** Prof. Marino Miculan\
> **Correlatori:** Dr. Matteo Paier, Dott. Elia Cal
>
> Università degli Studi di Udine · Dipartimento di Scienze Matematiche, Informatiche e Fisiche · A.A. 2025/2026

[📄 Leggi la tesi (PDF)](thesis_paviotti.pdf)

## Descrizione

A completamento delle informazioni presentate nella tesi, è stato predisposto il seguente *repository GitHub*, che raccoglie le principali risorse utilizzate e prodotte nel corso del lavoro, scelte in quanto significative per documentarne lo sviluppo e i risultati ottenuti. Di seguito viene presentata la struttura del repository, come già descritto all'interno dell'Appendice B (*Risorse, artefatti e risultati*) dell'elaborato.

## Struttura del repository

```text
.
├── thesis_paviotti.pdf
├── project_artifacts/
├── experimental_setup/
└── experimental_results/
```

| Elemento | Contenuto | Riferimento nella tesi |
| --- | --- | --- |
| `thesis_paviotti.pdf` | Copia digitale della tesi, identica al documento presentato | — |
| `project_artifacts/` | Artefatti dell'implementazione in forma completa | *BotScope: implementazione* (Capitolo 5) |
| `experimental_setup/` | Campioni, knowledge base e configurazioni dei LLM | *BotScope: valutazione* (Capitolo 6), *LLM e inferenza* (Appendice A) |
| `experimental_results/` | Report, log e Capture Module di ogni esecuzione | *BotScope: valutazione* (Capitolo 6) |

## Contenuto del repository

### `project_artifacts/`

La cartella mette a disposizione, nella loro forma completa, gli artefatti prodotti nell'ambito dell'implementazione, che nel Capitolo 5 della tesi sono stati descritti nei passaggi più importanti o solamente in sintesi.

- Definizione finale della **Botnet Interface**.
- **Code Templates** usati dal *Code Agent*, con le implementazioni di riferimento del modulo *Botnet* e del modulo *Message Parser*. Quest'ultima comprende anche l'enumerazione `Message Type` per la classificazione dei messaggi.
- **JSON Schema** completo che definisce il *Message Schema* dei comandi catturati, accompagnato dal subschema **IP Schema** per le informazioni sugli indirizzi IP dei bersagli degli attacchi.
- Implementazione della classe **`IP Lookup`**, attraverso la quale i *Capture Module* possono popolare i campi dell'IP Schema.
- **Prompt Archive**, al cui interno sono riuniti tutti i system prompt e gli user prompt utilizzati, organizzati secondo la stessa struttura seguita nella trattazione della Sezione 5.9 della tesi.
- Elenco del **sottoinsieme dei tool MCP** di analisi statica esposti dal *SRE Framework*, attraverso il plugin [`ghidra-mcp`](https://github.com/bethington/ghidra-mcp), e usati nell'implementazione attuale.
- **Dockerfile** e codice Python necessario alla creazione del container destinato al *Sandbox Environment*.

### `experimental_setup/`

La cartella raccoglie le risorse utilizzate come riferimento per la preparazione e l'impostazione della fase sperimentale descritta nel Capitolo 6 della tesi.

- File **`malware_samples.md`**, che riporta l'elenco dei campioni e le relative informazioni principali. Il contenuto riprende quello presentato nella Tabella 6.4 della tesi, integrandolo con i collegamenti URL ai report dei campioni disponibili su [VirusTotal](https://www.virustotal.com/) e [MalwareBazaar](https://bazaar.abuse.ch/). Le due piattaforme offrono ulteriori informazioni di threat intelligence relative ai campioni; MalwareBazaar offre anche la possibilità di scaricarli.
- **YARA rule** usata dal *Classifier* per riconoscere la famiglia di botnet *Mirai*.
- File della **Knowledge Base** per la famiglia di botnet *Mirai*, utilizzato come conoscenza aggiuntiva dal *SRE Agent*.
- **Configurazioni vLLM** usate per il deployment dei LLM [Qwen 3.6-27B](https://qwen.ai/blog?id=qwen3.6-27b) e [DeepSeek-V4-Flash Preview](https://api-docs.deepseek.com/news/news260424).
- **Parametri di campionamento** dei LLM, sia quelli inizialmente proposti sia quelli effettivamente utilizzati negli esperimenti, come già documentato nell'Appendice A della tesi.

### `experimental_results/`

La cartella raccoglie tutti i risultati delle esecuzioni effettuate nel corso della fase sperimentale e utilizzati per le valutazioni del Capitolo 6 della tesi. Per ciascun campione è presente una cartella dedicata, organizzata in base al LLM impiegato, `Q3627` (Qwen 3.6-27B) o `DS4FP` (DeepSeek-V4-Flash Preview).

```text
experimental_results/
└── <sample>/
    ├── Q3627/
    └── DS4FP/
        ├── reports/
        ├── logs/
        ├── <sample>.py         # Modulo Botnet
        └── parser.py           # Modulo Message Parser
```

Per ogni combinazione di campione e LLM sono presenti:

- **SRE Reports**: gli output delle attività di *Transport Analysis* e *Communication Analysis* della *Reversing Task*. Per i campioni *stripped* ci sono anche i report sintetici prodotti dai due agentic loop dedicati alla *Renaming Task*.
- **Logging Files** delle attività svolte dal LLM nel *SRE Agent*, sia come conversazioni complete in formato JSON, sia in un formato semistrutturato più facile da consultare.
- **Capture Module** prodotto dal *Code Agent*: il modulo principale *Botnet* è contenuto in `sample_name.py`, il modulo *Message Parser* in `parser.py`.

## Uso responsabile

Il repository documenta un'attività di ricerca sull'analisi di malware e sulla generazione di moduli che comunicano con infrastrutture di botnet. È pubblicato a soli fini di ricerca, documentazione e trasparenza.

- Il repository non distribuisce campioni di malware, ma solo riferimenti ai report pubblici su VirusTotal e MalwareBazaar.
- I campioni vanno maneggiati solo in ambienti controllati.
- I moduli generati interagiscono con infrastrutture C&C di IoT botnet reali e vanno eseguiti con cautela.
- Chi riutilizza il materiale è responsabile del rispetto delle leggi applicabili e della sicurezza dei propri sistemi.
- Il materiale è fornito *as is*, senza garanzie di alcun tipo.

## Citazione

Se utilizzi queste risorse, cita la tesi:

```bibtex
@thesis{paviotti2026botscope,
  author      = {Paviotti, Omar},
  title       = {Generazione agentica di moduli per la cattura dei comandi delle botnet},
  type        = {Tesi di Laurea},
  institution = {Università degli Studi di Udine},
  year        = {2026},
  note        = {Relatore: Marino Miculan. Correlatori: Matteo Paier, Elia Cal.},
  url         = {https://github.com/xomarpvt/bachelor-thesis}
}
```

La citazione è disponibile anche in formato [CFF](CITATION.cff), esportabile in BibTeX e APA dal pulsante *Cite this repository*.

## Licenza

© 2026 Omar Paviotti

Questo lavoro è distribuito con licenza [Creative Commons 4.0 License Attribution-NonCommercial-ShareAlike](https://creativecommons.org/licenses/by-nc-sa/4.0/), la stessa della tesi. Vedi il file [`LICENSE`](LICENSE).
