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

Passwords are not stored anywhere. They unlock the file. **If you forget the admin password, the data can't be recovered**, so keep a backup of `data.json` and write your passwords down somewhere safe.

## Publish on GitHub (first time)

1. Create a new repository on GitHub, for example `life-line`.
2. Upload `index.html`, `style.css` and `script.js` (and this README).
3. Go to **Settings → Pages**, choose **Deploy from a branch**, branch `main`, folder `/ (root)`, and save.
4. Open the site link GitHub shows you (`https://<your-name>.github.io/life-line/`).
5. Since there's no `data.json` yet, the site asks for an **admin password** and a **viewer password**. Set them.
6. Add your events, press **Save file**, then upload the downloaded `data.json` to the repository.

## Autosave to GitHub (recommended)

Once this is set up, every change saves straight to the repository, with no downloading or uploading.

**1. Create a token (one time)**

1. On GitHub, go to **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
2. **Expiration:** pick a date, for example 1 year.
3. **Repository access:** *Only select repositories* → choose `life-line` only.
4. **Permissions → Repository permissions → Contents:** *Read and write*. Leave everything else at *No access*.
5. Generate the token and copy it. It starts with `github_pat_`.

**2. Connect**

Log in as **admin**, press **GitHub**, check the account and repository names, paste the token, and press **Connect**. The badge at the top shows **Saved** or **Saving…**.

**How the token stays safe**

- It is never put into the repository or any file.
- It is stored only in this browser, encrypted with your admin password. The viewer can't use it.
- It can only change files in this one repository.
- To remove it from a browser, press **GitHub → Disconnect this browser**. To cancel it everywhere, delete the token on GitHub.
- Use autosave only on your own computer. On a new computer, connect again with the same token or a new one.

Every save is a commit, so GitHub keeps the full history of earlier versions.

## Updating without autosave

1. Log in as **admin** and make your changes. The **Save file •** button shows when something is unsaved.
2. Press **Save file** and upload the new `data.json` to the repository, replacing the old one.
3. After a minute or two, the site shows the new version.

## Moving data from the Claude artifact

In the Claude artifact, press **Export**. Then log in here as admin, press **Import**, choose the exported file, and press **Save file**.

## Sharing

Send the site link and the **viewer** password, ideally in separate messages. The viewer sees the chart, the list and the notes, but can't change anything.

## Working offline

Open `index.html` from your computer (with `style.css` and `script.js` next to it). The site asks you to choose your `data.json`, then works the same way.
