# Kullanıcının cümlesinden shim kuralı yazmak

Kullanıcının gizli dediği şeyi `propose_rules` ile somut kurallara çevirirsiniz.
Bir yönetici dönen planı uygulayana kadar shim hiçbir şey yazmaz; uygulandıktan
sonra da kurallar, bir kişi zorunlu hale getirene kadar yalnızca sayar (`monitor`).

## Üç aşama

1. **Cümle.** Kullanıcı neyin dışarı çıkmaması gerektiğini kendi sözleriyle söyler.
2. **Somut liste.** Kuralları yalnızca kullanıcının gerçekten adını verdiği
   şeylerden çıkarırsınız: proje adları, ürün adları, kod biçimleri, veri türleri.
   Kullanıcının vermediği bir adı, kodu ya da listeyi asla uydurmayın.
3. **Onay.** Cümleyi ve kuralları `propose_rules` aracına gönderirsiniz. shim
   bunları denetler ve bir plan kimliği döndürür. Planı bir yönetici uygular.

## Örnek zorunlu

Her `term` ya da `pattern` kuralı için kullanıcıdan kuralın yakalaması gereken bir
cümle (`examples.match`) ve yakalamaması gereken bir cümle (`examples.no_match`)
isteyin. shim kuralı bunlarda ve sıradan ofis metninde çalıştırır; kendi örneğini
kaçıran, karşı örneği yakalayan ya da sıradan metinde tetiklenen kural bir soruyla
geri çevrilir.

## Üç tür

- `term`: tam kelimeler. `{"kind": "term", "match": {"terms": ["Atlas"], "label": "PROJECT"}}`.
  Türkçe ekler yakalanır: `Atlas`, `Atlas'ın` ve `Atlasta` biçimlerini de yakalar,
  `Atlasçılık` kelimesini asla yakalamaz. Büyük küçük harf fark etmez; bu yüzden karşı örnek kelimeyi hiç içermemeli: `atlas çizimi` de yakalanır.
- `pattern`: bir biçim. `{"kind": "pattern", "match": {"templates": ["PRJ-####"], "label": "PROJECT_CODE"}}`.
  Şablonda `#` bir rakam, `@` bir harf demektir; `\` sonraki karakteri olduğu gibi alır.
- `destination`: bazı hedeflere hiç gitmeyecek veri türleri.
  `{"kind": "destination", "match": {"entity_types": ["EMAIL_ADDRESS"]}, "scope": {"deployment_kinds": ["external"]}}`.
  Bir kapsam ister, metin örneği istemez.

Her kuralın ayrıca `id` (küçük harf, `a-z0-9_`), `name`, `action` (`monitor`,
`mask`, `block`) ve `scope` (her şey için `{}`) alanları vardır. `state` göndermeyin.

## Yanıtı okumak

- 201 `proposed`: kullanıcıya plan kimliğini ve planı bir yöneticinin uygulayacağını söyleyin.
- `questions` içeren `RULE_PROPOSAL_NEEDS_EXAMPLES`; her sorunun bir `reason` alanı var:
  - `no_rules`: cümle somut bir şeyin adını vermiyor. Hangi adların, kodların ya da
    belgelerin kastedildiğini sorun.
  - `missing_examples`: kuralın yakalaması gereken bir cümle isteyin.
  - `too_generic` (`term_index`): kelime bir bilgi türünü anlatıyor ("gizli",
    "müşteri"). Gerçek adı isteyin.
  - `too_broad`: kural sıradan metinde tetikleniyor. Daha dar bir biçim isteyin.
  - `example_not_matched` / `no_match_example_matched` (`example_index`): kural ile
    örnekler uyuşmuyor. Yazımı kullanıcıyla kontrol edin.
- `errors` (`path`, `code`) içeren `RULE_PROPOSAL_INVALID`: `path` alanını düzeltin.
- `CONFIG_FILE_MANAGED`: kurallar burada imzalı bir dosyadan geliyor; `validated_rules`
  listesini o dosyayı düzenleyen kişiye verin.
- `RULE_PROPOSAL_LIMIT`: bekleyen öneri çok; bir yöneticiden önce onları uygulamasını
  ya da bırakmasını isteyin.

Kullanıcıya sorun; tahmin etmeyin.

## Örnekler

"Atlas projesi gizli." cümlesi bir `term` kuralı olur:

```json
{"sentence": "Atlas projesi gizli.", "language": "tr", "rules": [
  {"id": "project_atlas", "name": "Atlas", "kind": "term", "action": "mask", "scope": {},
   "match": {"terms": ["Atlas"], "label": "PROJECT"},
   "examples": {"match": ["Atlas'ın teslim tarihi"], "no_match": ["Atlantik rotası"]}}]}
```

"Proje kodlarımız PRJ-1234 gibi." cümlesi `PRJ-####` şablonlu bir `pattern` kuralı olur;
örnekler "PRJ-4821 için rapor" ve "PRJ-48211".

"Müşteri e-postaları dış modellere gitmesin." cümlesi `EMAIL_ADDRESS` için,
`{"deployment_kinds": ["external"]}` kapsamlı ve `block` eylemli bir `destination` kuralı olur.

"Our pricing sheet must not leak; SKUs look like AB-12-3456." cümlesi `@@-##-####`
şablonlu bir `pattern` kuralı olur; örnekleri kullanıcı onaylar.

"Stratejik bilgilerimiz çıkmasın." cümlesinden kural çıkmaz: shim `no_rules` ya da
`too_generic` yanıtı verir. Hangi adların, kodların ya da belgelerin kastedildiğini sorun.
