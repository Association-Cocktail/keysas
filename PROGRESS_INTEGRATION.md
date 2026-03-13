# Guide d'intégration du système de progression KeySAS

## 📋 Vue d'ensemble

Ce système de progression permet de suivre en temps réel l'avancement de l'analyse des fichiers dans KeySAS, avec un feedback détaillé pour l'utilisateur final.

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ keysas-in   │────▶│keysas-transit│────▶│ keysas-out │
└─────────────┘     └──────────────┘     └─────────────┘
       │                    │
       │                    │
       ▼                    ▼
┌─────────────┐     ┌──────────────┐
│  progress_  │     │  progress_   │
│   in.json   │     │ transit.json │
└─────────────┘     └──────────────┘
       │                    │
       └────────┬───────────┘
                ▼
        ┌──────────────┐
        │keysas-backend│
        │  (WebSocket) │
        └──────────────┘
                │
                ▼
        ┌──────────────┐
        │ Frontend Vue │
        └──────────────┘
```

## 🔧 Installation

### 1. Compiler le projet avec le nouveau module

```bash
cd /mnt/c/Users/rsclison/DEV/keysas
cargo build --release
sudo make install
```

### 2. Créer le répertoire pour les fichiers de progression

```bash
sudo mkdir -p /var/lock/keysas
sudo chown keysas-in:keysas-in /var/lock/keysas
sudo chmod 755 /var/lock/keysas
```

### 3. Redémarrer les services

```bash
sudo systemctl restart keysas-in.service
sudo systemctl restart keysas-transit.service
sudo systemctl restart keysas-out.service
sudo systemctl restart keysas-backend.service
```

## 📊 Format des fichiers de progression

### /var/lock/keysas/keysas-in-progress.json

```json
{
  "daemon_name": "keysas-in",
  "total_files": 10,
  "processed_files": 5,
  "failed_files": 0,
  "current_file": {
    "filename": "document.pdf",
    "step": "Hashing",
    "step_description": "Calcul du hash SHA256...",
    "percentage": 10,
    "start_time": "13-03-2026_14-30-25",
    "current_time": "13-03-2026_14-30-26"
  },
  "queue": ["file2.pdf", "file3.jpg", "file4.mp4"],
  "completed": ["file1.pdf", "file2.jpg"],
  "is_processing": true
}
```

### /var/lock/keysas/keysas-transit-progress.json

```json
{
  "daemon_name": "keysas-transit",
  "total_files": 10,
  "processed_files": 3,
  "failed_files": 1,
  "current_file": {
    "filename": "document.pdf",
    "step": "AntivirusScan",
    "step_description": "Scan antivirus en cours...",
    "percentage": 50,
    "start_time": "13-03-2026_14-30-27",
    "current_time": "13-03-2026_14-30-32"
  },
  "queue": ["file5.pdf", "file6.jpg"],
  "completed": ["file1.pdf", "file2.jpg", "file3.mp4"],
  "is_processing": true
}
```

## 🎨 Intégration Frontend

### 1. Copier le composant de progression

```bash
cp PROGRESS_FRONTEND_EXAMPLE.vue keysas-frontend/src/components/KeysasProgress.vue
```

### 2. Importer et utiliser le composant

Dans `keysas-frontend/src/App.vue` ou votre page principale :

```vue
<template>
  <div id="app">
    <!-- Autre contenu... -->

    <!-- Composant de progression -->
    <KeysasProgress :status="globalStatus" />
  </div>
</template>

<script>
import KeysasProgress from './components/KeysasProgress.vue';

export default {
  name: 'App',
  components: {
    KeysasProgress
  },
  data() {
    return {
      globalStatus: {}
    };
  },
  mounted() {
    // Connexion WebSocket existante
    this.connectWebSocket();
  },
  methods: {
    connectWebSocket() {
      const ws = new WebSocket('ws://localhost:3012');

      ws.onmessage = (event) => {
        this.globalStatus = JSON.parse(event.data);

        // Les nouvelles propriétés sont disponibles :
        // - this.globalStatus.progress_in
        // - this.globalStatus.progress_transit
      };
    }
  }
};
</script>
```

## 📈 États d'analyse disponibles

| État | Description | Pourcentage |
|------|-------------|-------------|
| `Pending` | En attente de traitement | 0% |
| `Hashing` | Calcul du hash SHA256 | 10% |
| `CheckingSize` | Vérification de la taille | 20% |
| `CheckingFileType` | Vérification du type de fichier | 30% |
| `AntivirusScan` | Scan antivirus ClamAV | 50% |
| `YaraScan` | Scan YARA | 75% |
| `VerifyingSignature` | Vérification de la signature | 90% |
| `Complete` | Analyse terminée avec succès | 100% |
| `Failed` | Analyse échouée | 0% |

## 🔍 Surveillance et débogage

### Vérifier les fichiers de progression en temps réel

```bash
# Surveiller keysas-in
watch -n 1 'cat /var/lock/keysas/keysas-in-progress.json | jq'

# Surveiller keysas-transit
watch -n 1 'cat /var/lock/keysas/keysas-transit-progress.json | jq'
```

### Vérifier les logs des daemons

```bash
# keysas-in
sudo journalctl -u keysas-in.service -f

# keysas-transit
sudo journalctl -u keysas-transit.service -f

# keysas-out
sudo journalctl -u keysas-out.service -f
```

### Tester avec des fichiers

```bash
# Copier des fichiers de test
cp test.pdf /var/local/in/
cp test.jpg /var/local/in/

# Surveiller la progression
tail -f /var/log/syslog | grep keysas
```

## 🎯 Personnalisation

### Modifier la fréquence de mise à jour

Dans `keysas_lib/src/progress.rs`, modifier la fréquence des mises à jour :

```rust
// Par défaut, chaque étape met à jour le fichier
// Pour ajouter un throttle :
pub fn update_step(&self, step: AnalysisStep) {
    if let Some(ref mut current) = self.current_file {
        let percentage = step.percentage();
        current.update_step(step, percentage);

        // Ajouter un throttle si nécessaire
        // if should_update() {
            let _ = self.update_progress_file(&self.progress_file);
        // }
    }
}
```

### Modifier les messages

Dans `keysas_lib/src/progress.rs`, modifier la méthode `description()` :

```rust
pub fn description(&self) -> String {
    match self {
        AnalysisStep::Pending => "⏳ En attente...".to_string(),
        AnalysisStep::Hashing => "🔐 Vérification de l'intégrité...".to_string(),
        // ... personnaliser les autres messages
    }
}
```

## 🐛 Résolution de problèmes

### Les fichiers de progression ne sont pas créés

**Vérifier les permissions :**
```bash
ls -la /var/lock/keysas/
# Doit être accessible en écriture par les daemons
```

**Corriger si nécessaire :**
```bash
sudo chown keysas-in:keysas-in /var/lock/keysas/keysas-in-progress.json
sudo chown keysas-transit:keysas-transit /var/lock/keysas/keysas-transit-progress.json
```

### Le backend n'envoie pas la progression

**Vérifier que le backend compile :**
```bash
cd keysas-backend
cargo build
```

**Vérifier les logs du backend :**
```bash
sudo journalctl -u keysas-backend.service -f
```

### Le frontend n'affiche rien

**Ouvrir la console du navigateur et vérifier :**
- Erreurs JavaScript
- Messages WebSocket
- Réponse JSON du backend

**Vérifier la structure JSON :**
```bash
# Tester manuellement le WebSocket
wscat -c ws://localhost:3012
# Ctrl+C pour quitter
```

## 📚 Ressources supplémentaires

- Documentation Rust : [serde_json](https://docs.rs/serde_json/)
- Documentation Vue.js : [WebSocket](https://vuejs.org/guide/built-ins/transition.html#javascript-hooks)
- Design System : Bootstrap Icons pour les icônes

---

**Version** : 1.0.0
**Date** : 13 Mars 2026
**Auteur** : KeySAS Development Team
