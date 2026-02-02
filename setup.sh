#!/bin/bash

# LGRE² Marketplace - Script de démarrage rapide
# Power by Guy Stephane NGUENE Makondo

echo "========================================="
echo "  🔷 LGRE² Marketplace Setup 🔷"
echo "  Power by Guy Stephane NGUENE Makondo"
echo "========================================="
echo ""

# Vérifier Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js n'est pas installé"
    echo "Veuillez installer Node.js depuis https://nodejs.org"
    exit 1
fi

echo "✅ Node.js détecté: $(node --version)"

# Vérifier npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm n'est pas installé"
    exit 1
fi

echo "✅ npm détecté: $(npm --version)"

# Créer les dossiers nécessaires
echo ""
echo "📁 Création des dossiers..."
mkdir -p uploads/listings uploads/profiles public

# Copier le fichier HTML
if [ -f "index-v2.html" ]; then
    cp index-v2.html public/index.html
    echo "✅ Frontend copié dans public/"
else
    echo "⚠️  index-v2.html non trouvé"
fi

# Vérifier le fichier .env
if [ ! -f ".env" ]; then
    echo ""
    echo "⚠️  Fichier .env non trouvé"
    echo "📝 Création du fichier .env depuis .env.example..."
    
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✅ Fichier .env créé"
        echo ""
        echo "⚠️  IMPORTANT: Editez le fichier .env et configurez:"
        echo "   - EMAIL_PASSWORD (mot de passe d'application Gmail)"
        echo "   - JWT_SECRET (changez en production)"
    else
        echo "❌ .env.example non trouvé"
    fi
fi

# Installer les dépendances
echo ""
echo "📦 Installation des dépendances..."
npm install

# Vérifier MongoDB
echo ""
echo "🔍 Vérification de MongoDB..."
if ! command -v mongod &> /dev/null; then
    echo "⚠️  MongoDB n'est pas détecté dans le PATH"
    echo "   Assurez-vous que MongoDB est installé et en cours d'exécution"
else
    echo "✅ MongoDB détecté"
fi

echo ""
echo "========================================="
echo "  ✅ Configuration terminée!"
echo "========================================="
echo ""
echo "Pour démarrer le serveur:"
echo "  npm start          # Mode production"
echo "  npm run dev        # Mode développement (auto-reload)"
echo ""
echo "Le site sera disponible sur:"
echo "  http://localhost:3000"
echo ""
echo "N'oubliez pas de:"
echo "  1. Configurer EMAIL_PASSWORD dans .env"
echo "  2. S'assurer que MongoDB est en cours d'exécution"
echo ""
echo "📞 Contact: +237 687870254"
echo "✉️  Email: guystephanenguenemakondo@gmail.com"
echo ""
