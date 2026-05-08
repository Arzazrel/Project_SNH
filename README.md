# Project_SNH

## **Description** 

Project for the system and network hacking exam of the AIDE master's degree at the University of Pisa, year 2025-2026.

## **Hardware used**

CPU: Intel(R) Core(TM) i7-10870H CPU @ 2.20GHz 2.21 GHz RAM: 16 GB GPU: RTX 3060 6GB laptop

## **Enviroments Settings**
Project developed on the Kali Linux VM used during the course. The environment used had these software and these versions.

- apache2
Server version: Apache/2.4.58 (Debian)
                                                                                                                                                                                                                                            
- mysql
mysql  Ver 15.1 Distrib 10.11.4-MariaDB, for debian-linux-gnu (x86_64) using  EditLine wrapper
                                                                                                                                                                                                                                            
- php              
PHP 8.2.10 (cli)
Zend Engine v4.2.10, Copyright (c) Zend Technologies with Zend OPcache v8.2.10, Copyright (c), by Zend Technologies
                                                                              

## **The folder contains:**  
  
- Code/			: contain all codes
-- config/  		: Configuration files
-- includes/        : reusable functions (eg. input sanitization, session validation)
-- logs/            : contain log files 
-- uploads/         : Storage for MP3 files
-- public/          : all public .php files
-- database/        : SQL script, initialization and backup (schema.sql)
- Documentation/: contain all project documentations
-- design/          : Diagrams and architectural logic
-- security/        : Risk analysis and countermeasures document
-- manual.pdf       : User/Admin manual
- .gitignore	
- README.md

## **DB setup**

The application uses **MariaDB** (MySQL) for persistence management.

- initialization: starting the database daemon on Kali.
```bash
sudo systemctl start mariadb
```
- Structure Creation: Import the provided schema into the database/ folder. This command will create the music_wave_DB database and populate the tables with test users:
```bash
sudo mariadb -u root < code/database/schema.sql
```

## **Developer's notes**  
  
Work In Progress

## **Developers:**  

- Alessandro Diana