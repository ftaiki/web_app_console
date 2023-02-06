from datetime import datetime, timedelta
from flask import Flask, flash, redirect, request, render_template, has_request_context
from flask.logging import default_handler
import sqlite3
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

#conn = sqlite3.connect('log.db')
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'

#ログデータが飛んでくる
@app.route("/")
def home():
    return redirect("/index")

@app.route("/index", methods=['GET'])
def index_get():
    conn = sqlite3.connect('log.db')
    sql = "SELECT * FROM logs"
    
    #logデータの取得
    curs = conn.execute(
        sql
    ).fetchall()
    db = curs
    
    #今日の攻撃検知数
    sql = "SELECT COUNT(*) FROM count_logs WHERE date(time) = date('now', '+9 hours')"
    curs = conn.execute(
        sql
    ).fetchall()
    db_today_anom = curs[0]
    
    #昨日の攻撃検知数
    sql = "SELECT COUNT(*) FROM count_logs WHERE date(time) = date('now', '+9 hours', '-1 day')"
    curs = conn.execute(
        sql
    ).fetchall()
    db_yesterday_anom = curs[0]
    
    #今月の攻撃検知数
    sql = "SELECT COUNT(*) FROM count_logs WHERE strftime('%Y-%m',date(time)) = strftime('%Y-%m',date('now', '+9 hours'))"
    curs = conn.execute(
        sql
    ).fetchall()
    db_month_anom = curs[0]
    
    #昨月の攻撃検知数
    sql = "SELECT COUNT(*) FROM count_logs WHERE strftime('%Y-%m',date(time)) = strftime('%Y-%m',date('now', '+9 hours', '-1 months'))"
    curs = conn.execute(
        sql
    ).fetchall()
    db_last_month_anom = curs[0]
    
    #今日の全体のアクセス数
    sql = "SELECT COUNT(*) FROM logs WHERE date(time) = date('now', '+9 hours')"
    curs = conn.execute(
        sql
    ).fetchall()
    db_today = curs[0]
    
    #昨日の全体のアクセス数
    sql = "SELECT COUNT(*) FROM logs WHERE date(time) = date('now', '+9 hours', '-1 day')"
    curs = conn.execute(
        sql
    ).fetchall()
    db_yesterday = curs[0]
    
    #今月の全体のアクセス数
    sql = "SELECT COUNT(*) FROM logs WHERE strftime('%Y-%m',date(time)) = strftime('%Y-%m',date('now', '+9 hours'))"
    curs = conn.execute(
        sql
    ).fetchall()
    db_month = curs[0]
    
    #昨月の全体のアクセス数
    sql = "SELECT COUNT(*) FROM logs WHERE strftime('%Y-%m',date(time)) = strftime('%Y-%m',date('now', '+9 hours', '-1 months'))"
    curs = conn.execute(
        sql
    ).fetchall()
    db_last_month = curs[0]
    
    return render_template('index.html', db=db, db_today=db_today, db_yesterday=db_yesterday, db_month=db_month, db_last_month=db_last_month,
                        db_today_anom=db_today_anom, db_yesterday_anom=db_yesterday_anom, db_month_anom=db_month_anom, db_last_month_anom=db_last_month_anom)

@app.route("/detection", methods=['POST'])
def detection():
    #POSTでアクセスログを貰う
    loginfo = [ request.remote_addr,
                request.method,
                request.url,
                request.path
            ]
    event1 = request.form['event1']
    event2 = request.form['event2']
    
    event = ' '.join(loginfo)
    event += ' '+event1
    #もしevent2が入っていれば
    if event2:
        event+=' ,'+event2
    print(event)
    
    #モデルにペイロードをぶち込む
    alert = 'normal'
    #ペイロードをうまいことTf-id-f Vectorizerにかけてからpredictする関数を呼び出す
    result = predict(event)
    if event2 :
        result2 = predict(event2)
    
    if result == 1:
        alert = 'abnormal'
    if result2 == 1:
        alert = 'abnormal'
    
    #データベースへの挿入
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('log.db')
    curs = conn.cursor()
    data = [event, alert, now]
    curs.execute(
        "INSERT INTO logs(event, alert, time) values(?, ?, ?)",data
    )
    conn.commit()
    conn.close()
    return redirect("/index")

@app.route("/detection", methods=['GET'])
def see_detection():
    return  render_template("detection.html")


#モデルでペイロードから攻撃検知して1か0を返す
def predict(payload):
    df = pd.read_csv('app/dataset/payload_full.csv')
    df1 = pd.read_csv('app/dataset/payload_train.csv')
    train_rows = ((df.attack_type=='norm') | (df.attack_type=='sqli'))
    df = df[train_rows]

    test_train_rows = ((df1.attack_type=='norm') | (df1.attack_type=='sqli'))
    df1 = df1[test_train_rows]
    #payload, length, attack_typeになるはず
    df_y = df[['label']]
    df1_y = df1[['label']]

    df_x = df.iloc[:,:-1]
    df1_x = df1.iloc[:,:-1]

    X_all = pd.concat([df_x, df1_x])
    y_all = pd.concat([df_y, df1_y])
    
    X = X_all['payload']
    vec_opts = {
    "ngram_range":(1,1),
    "analyzer":"char",
    "min_df":0.1
    }
    v = TfidfVectorizer(**vec_opts)
    
    payload_list = [payload]
    columns=['payload']
    sqli = pd.DataFrame(payload_list,columns=columns)
    new_df = sqli['payload']
    X = X.append(new_df,ignore_index = True)
    #ベクトル化する
    X = v.fit_transform(X)
    #この関数の引数のベクトル化した値を変数に格納
    validation_data = X[-1]
    
    model = joblib.load('app/model/model.pickle')
    pred = model.predict(validation_data)
    #結果を1か0で返す
    result = 0
    if pred >=0.95:
        result = 1
    return result
    
    