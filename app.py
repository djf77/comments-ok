# app.py
from flask import Flask, request, session, jsonify
from mysql.connector import connect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from gevent import pywsgi

config = {
    'user': 'root',
    'password': '123456',
    'host': '127.0.0.1',
    'database': 'board',
    'auth_plugin': 'mysql_native_password'
}


app = Flask(__name__)
app.config['SECRET_KEY'] = '123456'

CORS(app)


# 自定义错误
class HttpError(Exception):
    def __init__(self, status_code, message):
        super().__init__()
        self.message = message
        self.status_code = status_code

    def to_dict(self):
        return {
            'status': self.status_code,
            'msg': self.message
        }


# 注册一个错误处理器
@app.errorhandler(HttpError)
def handle_http_error(error):
    response = jsonify(error.to_dict())  # 创建一个Response实例
    response.status_code = error.status_code  # 修改HTTP状态码
    return response


def get_connection():
    conn = connect(user=config.get('user'), password=config.get('password'),
                   database=config.get('database'), auth_plugin=config.get('auth_plugin'))
    cursor = conn.cursor()

    return conn, cursor


# 注册接口
@app.route('/add', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    sex = data.get('sex')
    age = data.get('age')
    address = data.get('address')

    # 获取数据库连接
    conn, cursor = get_connection()

    # 判断用户名是否存在
    cursor.execute('select count(*) from `users` where `username`=%s', (username,))
    count = cursor.fetchone()
    if count[0] >= 1:
        raise HttpError(400, 'username参数已存在')
    if username is None:
        raise HttpError(400, '缺少参数 username')
    if password is None:
        raise HttpError(400, '缺少参数 password')
    if sex is None:
        raise HttpError(400, '缺少参数 sex')
    if age is None:
        raise HttpError(400, '缺少参数 age')
    if address is None:
        raise HttpError(400, '缺少参数 address')

    # 插入数据库与加密
    cursor.execute('insert into `users`(`username`, `password`, `sex`, `age`, `address`) values (%s, %s, %s, %s, %s)',
                   (username, generate_password_hash(password), sex, age, address))
    conn.commit()

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '注册成功'


# 登录接口
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    # 获取数据库连接
    conn, cursor = get_connection()

    # 获取传入的用户的密码和id
    cursor.execute('select `id`, `password` from `users` where `username`=%s', (username,))
    values = cursor.fetchone()

    # 如果数据库中没有这个用户，则fetchone函数会返回None
    if values is None:
        raise HttpError(400, '用户名或密码错误')

    user_id = values[0]  # 用户的id
    pwd = values[1]  # 数据库中的密码

    # 判断
    if not check_password_hash(pwd, password):  # 如果密码不同
        raise HttpError(400, '用户名或密码错误')
    session['username'] = username
    session['user_id'] = user_id

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '登录成功'


# 个人信息界面
@app.route('/me', methods=['GET'])
def get_information():
    username = session.get('username')
    # 获取数据库连接
    conn, cursor = get_connection()
    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')
    # 数据库操作
    cursor.execute('SELECT `username`, `sex`, `age`, `address` from `users` where `username`=%s', (username,))
    data = cursor.fetchall()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    response = jsonify(data)
    return response


# 修改用户名
@app.route('/username', methods=['PUT'])
def change_username():
    data = request.get_json(force=True)
    username = data.get('username')

    # 获取数据库连接
    conn, cursor = get_connection()

    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')

    # 判断用户名是否存在
    cursor.execute('select count(*) from `users` where id=%s', (session.get('user_id'), ))
    count = cursor.fetchone()[0]
    if count >= 1:
        raise HttpError(400, 'username参数已存在')

    # 根据登录时储存的user_id在where子句中定位到具体的用户并更新他的用户名
    cursor.execute('update `users` set `username`=%s where id=%s', (username, session.get('user_id')))

    conn.commit()
    session['username'] = username

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '修改用户名成功'


# 修改密码
@app.route('/password', methods=['PUT'])
def change_password():
    data = request.get_json(force=True)
    password = data.get('password')

    # 获取数据库连接
    conn, cursor = get_connection()

    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')

    # 根据登录时储存的user_id在where子句中定位到具体的用户并更新他的密码
    cursor.execute('update `users` set `password`=%s where id=%s',
                   (generate_password_hash(password), session.get('user_id')))

    conn.commit()

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '修改密码成功'


# 修改个人信息
@app.route('/information', methods=['PUT'])
def change_information():
    username = session.get('username')
    data = request.get_json(force=True)
    sex = data.get('sex')
    age = data.get('age')
    address = data.get('address')

    # 获取数据库连接
    conn, cursor = get_connection()

    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')
    if sex is None:
        raise HttpError(400, '缺少参数 sex')
    if age is None:
        raise HttpError(400, '缺少参数 age')
    if address is None:
        raise HttpError(400, '缺少参数 address')

    # 数据库操作
    cursor.execute('update `users` set `sex`=%s, `age`=%s, `address`=%s where `username`=%s', (sex, age, address,
                                                                                               username))

    conn.commit()

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '修改个人信息成功'


# 留言界面
@app.route('/', methods=['GET'])
def show_comment():
    # 获取数据库连接
    conn, cursor = get_connection()
    # 数据库操作
    cursor.execute('select `comment_id`, `comments_author`, `comment`, `create_time`, `update_time` from comments')
    data = cursor.fetchall()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    response = jsonify(data)
    return response


# 上传留言
@app.route('/add_comment', methods=['POST'])
def add_comment():
    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')

    data = request.get_json(force=True)
    comments_author = session.get('username')
    comment = data.get('comment')

    # 获取数据库连接
    conn, cursor = get_connection()
    if comment is None:
        raise HttpError(400, '缺少参数 comment')
    # 插入数据库
    cursor.execute('insert into `comments`(`comments_author`, `comment`) values (%s, %s)',
                   (comments_author, comment))
    conn.commit()

    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '上传成功'


# 修改留言
@app.route('/update_comment', methods=["PUT"])
def update_comment():
    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')

    data = request.get_json(force=True)
    comment_id = data.get('id')
    comment = data.get('comment')
    comments_author = session['username']

    if comment is None:
        raise HttpError(400, '缺少参数 comment')
    if comment_id is None:
        raise HttpError(400, '缺少参数 id')

    # 获取数据库连接
    conn, cursor = get_connection()
    # 数据库操作
    cursor.execute('update `comments` set `comment`=%s where `comment_id`=%s and `comments_author`=%s',
                   (comment, comment_id, comments_author))
    conn.commit()
    # 关闭数据库连接
    cursor.close()
    conn.close()
    return '修改成功'


# 删除留言
@app.route('/delete_comment', methods=['DELETE'])
def delete_comment():
    # 如果session中没有user_id，说明用户未登录，返回401错误
    if session.get('user_id') is None:
        raise HttpError(401, '请先登录')
    data = request.get_json(force=True)
    comment_id = data.get('id')
    comments_author = session['username']
    if comment_id is None:
        raise HttpError(400, '缺少参数 id')
    # 获取数据库连接
    conn, cursor = get_connection()
    # 数据库操作
    cursor.execute('DELETE FROM `comments` where `comment_id`=%s and `comments_author`=%s',
                   (comment_id, comments_author))
    conn.commit()
    # 关闭数据库连接
    cursor.close()
    conn.close()

    return '删除成功'


if __name__ == '__main__':
    server = pywsgi.WSGIServer(('0.0.0.0', 5000), app)
    server.serve_forever()
