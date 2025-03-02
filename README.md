# Virologie
Projet étudiant (2600) d'injection de PE

Ce projet est à but éducatif uniquement et ne doit pas être utilisé à des fins malveillantes.

# Création de injpe.exe

```
nmake all
```

# Nettoyage total

```
nmake fclean
```

# Nettoyage des obj

```
nmake clean
```

# Injection dynamique de PE

Le programme `injpe.exe`, une fois lancé, injecte tous les fichiers `.exe` du dossier courant excepté lui-même.
1. Dans un premier temps, le programme récupère l'argument 0 (soit le nom de son propre exécutable).
2. Puis, il énumère les fichiers présents dans le dossier courant. 
3. S'il s'agit d'un fichier terminant par `.exe`, la fonction d'injection est lancée sur le fichier.
4. Le programme s'arrête lorsqu'il a énuméré tous les fichiers `.exe` du dossier.

# Injection de Process

Le programme `injpe.exe` injecte le processus `Notepad.exe` si aucun argument est fourni. 
Il est aussi possible de choisir le processus à injecter en passant le nom en argument (avec la casse et le .exe)

L'injection se déroule en 3 phases : 

-   Allocation d'un espace mémoire dans le process, de taille égale à celle du payload
-   Copie du payload dans la zone mémoire
-   Demande au système d'exécuter la charge utile via la création d'un remote thread, executé par notre process.

> L'injection de processus ne fonctionne pas pour le processus `CalculatorApp.exe`
