# Tortol Trade Journal

A comprehensive trading journal and habit tracker application designed to help traders build discipline and consistency.

## 📂 Project Location
Your project files are located at:
`/Users/jc.jaluague/Documents/Tortol Trade App`

## 🚀 Features
- **Trade Logging**: Detailed entry with setup, risk, and mental state tracking.
- **Dashboard**: Visual analytics including Win Rate, P&L, and Asset Class performance.
- **Habit Tracker**: "Atomic Habits" style tracker with target consistency and streaks.
- **Simulator**: Compounding and Wipeout risk simulator.
- **Cloud Sync**: Automatic data synchronization using Firebase (Firestore).

## 🛠️ Configuration (Firebase)
This app uses **Firebase** for data storage. Before deploying, you must configure your keys in `app.js`:

1.  Open `app.js`.
2.  Locate the `firebaseConfig` object at the top.
3.  Replace the placeholder values (`YOUR_API_KEY_HERE`, etc.) with your actual Firebase project details.

## 📦 How to Run Locally
1.  Open a terminal in the project folder.
2.  Run a local Python server:
    ```bash
    python3 -m http.server 8080
    ```
3.  Open your browser to `http://localhost:8080`.

## 🌐 Deploying to GitHub Actions / Pages
You can host this app for free using GitHub Pages.

1.  **Initialize Git**:
    ```bash
    cd "/Users/jc.jaluague/Documents/Tortol Trade App"
    git init
    git add .
    git commit -m "Initial commit"
    ```
2.  **Create Repository**:
    - Go to [GitHub.com](https://github.com) and create a new repository (e.g., `tortol-trade-journal`).
    - Copy the remote URL (e.g., `https://github.com/StartYourTrade/tortol-trade-journal.git`).
3.  **Push Code**:
    ```bash
    git branch -M main
    git remote add origin <YOUR_REPO_URL>
    git push -u origin main
    ```
4.  **Enable Pages**:
    - Go to your Repository **Settings** > **Pages**.
    - Under "Source", select `main` branch.
    - Click **Save**.
    - Your app will be live at `https://<username>.github.io/<repo-name>/`.

> **Important**: Add your GitHub Pages domain (e.g., `username.github.io`) to your **Firebase Authentication > Authorized Domains** list in the Firebase Console to allow logins to work.
