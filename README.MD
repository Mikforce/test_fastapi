# Тестовое задание

Test Task for Webtronics FastAPI candidate

	We are inviting you to assess your knowledge and solve the task below. Please pay attention to requirements for technology, code, your solution submission and don’t forget to visit the “bonus” section! You will need to upload your solution to Github. Good luck and feel free to be as creative as you think you should be!
TASK 
Description
	Create a simple RESTful API using FastAPI for a social networking application
Functional requirements:
There should be some form of authentication and registration (JWT, Oauth, Oauth 2.0, etc..)
As a user I need to be able to signup and login
As a user I need to be able to create, edit, delete and view posts
As a user I can like or dislike other users’ posts but not my own 
The API needs a UI Documentation (Swagger/ReDoc)

Bonus section (not required):
Use https://clearbit.com/platform/enrichment for getting additional data for the user on signup
Use emailhunter.co for verifying email existence on registration
Use an in-memory DB for storing post likes and dislikes (As a cache, that gets updated whenever new likes and dislikes get added) 

Technology Requirements
Tasks should be completed:
Using FastAPI 0.50.0+
With any DBMS (Sqlite, PostgreSQL, MySQL)
Uploaded to GitHub
Requirements
When implementing your solution, please make sure that the code is:
Well-structured
Contains instructions (best to be put into readme.md) about how to deploy and test it
Clean
The program you implement must be a complete program product, i.e. should be easy to install, provide for the handling of non-standard situations, be resistant to incorrect user actions, etc.
TASKS SUBMISSION
In order to submit completed tasks, please, create a public GitHub repository and input the link in the form


## Как запустить

1. Склонируйте репозиторий
2. активирйте виртуальне окружение  env\Scripts\activate.bat
3. pip install -r requirements.txt
4. в папке app реализованно тестовое с бонусом
5. Запустите приложение python main.py
6. zapros.py содержит запросы
7. test.py содержит тесты
8. доступ к пользовательскому интерфейсу Swagger по адресу /docs и ReDoc по адресу /redoc
9. в папке app2 реализованно тестовое без бонусов



## Автор
Толпеев Иван
