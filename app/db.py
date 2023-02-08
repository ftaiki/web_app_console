import sqlite3

conn = sqlite3.connect('../log.db')

curs = conn.cursor()

#curs.execute(
#    'DROP TABLE logs'
#)

#logs(id, event, alert, created TIMESTAMP DEFAULT(datetime(CURRENT_TIMESTAMP, 'localtime')))
#curs.execute(
#    "CREATE TABLE logs(id INTEGER PRIMARY KEY AUTOINCREMENT, event String, alert String, time TIMESTAMP DEFAULT (datetime(CURRENT_TIMESTAMP,'localtime')))"
#)


#検出したログ件数.主キーはアラートのレベル
#alertと日時だけ入れる
curs.execute(
    "CREATE TABLE count_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, alert String, time TIMESTAMP)"
)


curs.execute(
    'SELECT * FROM count_logs'
)
db = curs.fetchall()
print(db)
conn.commit()

curs.close()
conn.close()
