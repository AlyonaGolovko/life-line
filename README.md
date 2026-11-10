# My Life Line

A private timeline of life events by age, with an emotion score from −5 to +5 for each event.

- `index.html`, `style.css` and `script.js` are the website (page, styles and code). Keep them together in the same folder.
- `data.json` holds your events, **encrypted**. It's created the first time you open the site.

Nobody can read your events from the repository. Without a password, `data.json` is unreadable text.

## Logins

| Name   | Can do                                      |
|--------|---------------------------------------------|
| admin  | add, edit and delete events, change passwords |
| viewer | look only                                   |

Reloading the page keeps you logged in. You're asked for the password again when you close the tab, press "Log out", or 12 hours after logging in.

## Working offline

Open `index.html` from your computer (with `style.css` and `script.js` next to it). The site asks you to choose your `data.json`, then works the same way.
