# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import logging
from typing import Dict, Iterable

logger = logging.getLogger(__name__)

_2016_v1_en = """
<p>The following generally applies:</p>
<ul>
    <li>that all usage of user accounts follow Sweden's laws and by-laws,</li>
    <li>that all personal information that you provide, such as name and contact information shall be truthful,</li>
    <li>that user accounts, password, security keys and codes are individual and shall only be used by the intended individual,</li>
    <li>that SUNET's ethical rules regulate the "other" usage. SUNET judges unethical behaviour to be when someone</li>
    <ul>
        <li>attempts to gain access to network resources that they do not have the right to</li>
        <li>attempts to conceal their user identity</li>
        <li>attempts to interfere or disrupt the intended usage of the network</li>
        <li>clearly wastes available resources (personnel, hardware or software)</li>
        <li>attempts to disrupt or destroy computer-based information</li>
        <li>infringes on the privacy of others</li>
        <li>attempts to insult or offend others</li>
    </ul>
</ul>

<p>Any person found violating or suspected of violating these rules can be disabled from eduID.se for investigation. Furthermore, legal action can be taken.</p>
"""

_2016_v1_sv = """
<p>För eduID.se gäller generellt:</p>

<ul>
    <li>att all användning av användarkonton ska följa Sveriges lagar och förordningar,</li>
    <li>att man är sanningsenlig vid uppgivande av personlig information som namn, kontaktuppgifter el. dyl,</li>
    <li>att användarkonton, lösenord, säkerhetsnycklar och koder är personliga och får endast användas av innehavaren,</li>
    <li>att SUNET:s etiska regler reglerar övrig tillåten användning. SUNET bedömer som oetiskt när någon</li>
    <ul>
        <li>försöker få tillgång till nätverksresurser utan att ha rätt till det</li>
        <li>försöker dölja sin användaridentitet</li>
        <li>försöker störa eller avbryta den avsedda användningen av nätverken</li>
        <li>uppenbart slösar med tillgängliga resurser (personal, maskinvara eller programvara)</li>
        <li>försöker skada eller förstöra den datorbaserade informationen</li>
        <li>gör intrång i andras privatliv</li>
        <li>försöker förolämpa eller förnedra andra</li>
    </ul>
</ul>

<p>Den som överträder, eller misstänks överträda, ovanstående regler kan stängas av från eduID.se. Dessutom kan rättsliga åtgärder komma att vidtas.</p>
"""

tous = {
    '2016-v1': {'en': _2016_v1_en, 'sv': _2016_v1_sv},
    'test-version': {'en': 'test tou english', 'sv': 'test tou svenska'},
}


def get_tous(version: str, languages: Iterable[str]) -> Dict[str, str]:
    ret = {}
    for lang in languages:
        try:
            ret[lang] = tous[version][lang]
        except KeyError:
            logger.error(f'ToU with version {version} and lang {lang} not found')
            pass
    return ret
