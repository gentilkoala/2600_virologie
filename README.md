# Virologie
Projet d'injection de PE

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

# Injection de PE

Le programme `injpe.exe`, une fois lancé, injecte le programme `mapviewfile.exe` dans le dossier courant.
Si plusieurs `.exe` figure dans le dossier, ils seront également injectés.

# Injection de Process

Le programme `injpe.exe` injecte le processus "Notepad.exe" si aucun argument est fourni. 
Il est aussi possible de choisir le processus à injecter en passant le nom en argument (avec la casse et le .exe)

L'injection se déroule en 3 phases : 

-   Allocation d'un espace mémoire dans le process, de taille égale à celle du payload
-   Copie du payload dans la zone mémoire
-   Demande au système d'exécuter la charge utile via la création d'un remote thread, executé par notre process.

> L'injection de processus ne fonctionne pas pour le processus `CalculatorApp.exe`
