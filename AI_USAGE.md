# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Used AI assistant to explain the STRIDE per element theory, clarify YAML parsing with PyYAML, and help draft the checker functions in tmcheck/core.py and the new threat titles for rawaj_scoring.yaml.

## What AI got wrong

The AI initially checked scores with isinstance(val, int), but in Python True is treated as an integer. I noticed this would bypass the score rules, so I changed the check to ensure booleans are rejected.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?

Because a database cannot pretend to be someone else because it doesn't initiate actions. Spoofing applies to the process connecting to it, while modifying the data is Tampering

2. Which of your eleven new threats would you fix first, and why that one?

I'll start with T37 because it allows privilege escalation inside the core zone, which has the highest impact on Rawaj Pay.