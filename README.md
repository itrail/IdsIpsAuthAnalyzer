# IdsIpsAuthAnalyzer

IdsIpsAuthAnalyzer to narzędzie mające zwiększać skuteczność w wykrywaniu ataków na konta, przede wszystkim ataków bruteforce/słownikowych. Program składa się z komponentu:

- IdsIpsAuthAnalyzerSenses - moduł mający na celu wykrywanie prób ataków na konta
I w przyszłości współpracować będzie z:

Program działa na oknach czasowych X minutowych przesuwanych co Y minut. Dane czytane są z kafki. Pomijane są wpisy z pustym protokołem, ponieważ wskazuje to na inny system logowania oraz wpisy z pustym ip z pewnych powodów. W przypadku ataku tylko z adresów, które będą w logach widnieć jako puste zobaczymy jako wynik wpis, o tym, że atak odbył się z jednego ip, co może wpływać negatywnie na postrzeganie skali ataku.

Ponadto obok działąją:

- IdsIpsDjangoPanel - panelem wizualizującym wyniki IdsIpsAuthAnalyzera oraz panelem decyzyjny, podejmującym na jego podstawie działania, np. wystawianie blokady.
- IdsIpsLocker - moduł, który miałby samodzielnie reagować na udane ataki, np. blokować IP. Byłby karmiony informacjami z poziomu panelu IdsIpsDjangoPanel.


