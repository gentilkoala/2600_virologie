public __end_of_code

injected segment read execute
        ; Ajout de la chaine de caracteres COUCOU suivi dun caractere nul
        db "COUCOU", 0

        ; Declaration d'un label __end_of_code pour marquer la fin du code
        __end_of_code label QWORD
            ; Reservatio de 8 octets pour le lable __end_of_code
            dq 0

injected ends

end