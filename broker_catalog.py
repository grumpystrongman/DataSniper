"""Curated free, first-party privacy request paths."""

CATALOG_VERSION = "2026-07-21"

# An entry belongs here only when the broker/publisher operates the URL and the
# request does not require a paid removal subscription. Runtime checks detect
# breakage and page changes; maintainers still review additions and changes.
BROKERS = [
    {"slug":"peopleconnect","name":"PeopleConnect family","covers":"TruthFinder, Instant Checkmate, Intelius, and US Search","url":"https://suppression.peopleconnect.us/","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email"},
    {"slug":"spokeo","name":"Spokeo","covers":"People-search profile suppression","url":"https://www.spokeo.com/optout","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email and profile URL"},
    {"slug":"whitepages","name":"Whitepages","covers":"Public people-search listings","url":"https://www.whitepages.com/suppression_requests","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"phone and profile URL"},
    {"slug":"beenverified","name":"BeenVerified","covers":"People-search listings and related brands","url":"https://www.beenverified.com/app/optout/search","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email"},
    {"slug":"radaris","name":"Radaris","covers":"People-search profile removal","url":"https://radaris.com/control/privacy","state":"all","days":30,"category":"people_search","removal_type":"delete","availability":"nationwide","verification":"account or email"},
    {"slug":"nuwber","name":"Nuwber","covers":"People-search profile removal","url":"https://nuwber.com/removal/link","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email and profile URL"},
    {"slug":"familytreenow","name":"FamilyTreeNow","covers":"Genealogy-style public profile suppression","url":"https://www.familytreenow.com/optout","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"profile selection"},
    {"slug":"fastpeoplesearch","name":"FastPeopleSearch","covers":"People-search listing removal","url":"https://www.fastpeoplesearch.com/removal","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email and profile URL"},
    {"slug":"truepeoplesearch","name":"TruePeopleSearch","covers":"People-search listing removal","url":"https://www.truepeoplesearch.com/removal","state":"all","days":30,"category":"people_search","removal_type":"suppress","availability":"nationwide","verification":"email and profile URL"},
    {"slug":"liveramp","name":"LiveRamp","covers":"Identity resolution, advertising audiences, and associated consumer data","url":"https://liveramp.com/privacy/my-privacy-choices","state":"all","days":45,"category":"upstream_broker","removal_type":"delete and opt out of sale","availability":"rights vary by jurisdiction","verification":"email and identity details"},
    {"slug":"epsilon","name":"Epsilon","covers":"Marketing profiles, purchase data, and advertising audiences","url":"https://legal.epsilon.com/dsr","state":"all","days":45,"category":"upstream_broker","removal_type":"delete and opt out of sale","availability":"rights vary by jurisdiction","verification":"identity questions"},
    {"slug":"transunion-privacy","name":"TransUnion consumer privacy","covers":"Marketing, identity, risk, and alternative-data privacy requests","url":"https://www.transunion.com/consumer-privacy","state":"all","days":45,"category":"credit_identity","removal_type":"delete or opt out","availability":"rights vary by jurisdiction","verification":"account, form, or phone"},
    {"slug":"lexisnexis-risk","name":"LexisNexis Risk Solutions","covers":"Public-record, identity, fraud, and risk data","url":"https://consumer.risk.lexisnexis.com/privacy","state":"all","days":45,"category":"public_records_risk","removal_type":"delete or opt out of sale","availability":"rights vary by jurisdiction","verification":"identity details"},
    {"slug":"california-drop","name":"California DROP","covers":"Bulk request to registered California data brokers","url":"https://privacy.ca.gov/drop/","state":"CA","days":90,"category":"state_registry","removal_type":"delete","availability":"California residents","verification":"California residency and identity"},
    {"slug":"optoutprescreen","name":"Prescreened credit offers","covers":"Credit and insurance prescreening opt-out","url":"https://www.optoutprescreen.com/","state":"all","days":7,"category":"credit_identity","removal_type":"opt out","availability":"nationwide","verification":"identity details"},
]

def broker_by_slug(slug: str) -> dict:
    return next(broker for broker in BROKERS if broker["slug"] == slug)
