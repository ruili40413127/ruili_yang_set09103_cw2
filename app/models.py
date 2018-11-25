# -*- coding:utf-8 -*-
from . import db, login_manager
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from datetime import datetime
import hashlib
from markdown import markdown
import bleach

class Permission:
    FOLLOW = 0x01             # 关注用户
    COMMENT = 0x02            # 在他人的文章中发表评论
    WRITE_ARTICLES = 0x04     # 写文章
    MODERATE_COMMENTS = 0x08  # 管理他人发表的评论
    ADMINISTRATOR = 0xff      # 管理者权限
    FORBID = 0x00             # 禁止任何行为

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=True, unique=True)
    default = db.Column(db.Boolean, default=False)      # 只有一个角色的字段要设为True,其它都为False
    permissions = db.Column(db.Integer)                 # 不同角色的权限不同
    users = db.relationship('User', backref='itsrole')  # Role对象引用users,User对象引用itsrole
                                                        # 是隐形存在的属性,一对多
    @staticmethod
    def insert_roles():
        roles = {
            'User':(Permission.FOLLOW|Permission.COMMENT|
                     Permission.WRITE_ARTICLES, True),     # 只有普通用户的default为True
            'Moderare':(Permission.FOLLOW|Permission.COMMENT|
                    Permission.WRITE_ARTICLES|Permission.MODERATE_COMMENTS, False),
            'Administrator':(0xff, False),
            'Forbid':(0x00, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)     # 代表关注者,与relationship的follower对应
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)     # 代表被关注者,与relationship的followed对应
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=True)
    password = db.Column(db.String, nullable=True)
    email = db.Column(db.String, nullable=True, unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String, nullable=True)
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy='dynamic',
                            cascade='all, delete-orphan')
    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    def to_json(self):
        user_json = {
            'url': url_for('api.get_user', id=self.id, _external=True),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'post_count': self.posts.count()
        }
        return user_json


    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.itsrole is None:
            if self.email == current_app.config['FLASK_ADMIN']:
                self.itsrole = Role.query.filter_by(permissions=0xff).first()
            else:
                self.itsrole = Role.query.filter_by(default=True).first()

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)
            db.session.commit()

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f is not None:
            db.session.delete(f)
            db.session.commit()

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id)\
                    .filter(Follow.follower_id == self.id)


    def can(self, permissions):
        return self.itsrole is not None and \
               (self.itsrole.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTRATOR)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&r={rating}&d={default}'.format(url=url, hash=hash,
                                                            size=size, rating=rating,
                                                            default=default)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirm_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True


    @staticmethod
    def generate_fake(count=10):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def generate_auth_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])



class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @staticmethod
    def from_json(json_body):
        body = json_body.get('body')
        if body is None or body == '':
            print ('error')
        return Comment(body=body)

    def to_json(self):
        comment_json = {
            'url': url_for('api.get_comment', id=self.id, _external=True),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp
        }
        return comment_json

    @staticmethod
    def on_body_changed(target, value, oldvalue, initiator):
        allow_tags = ['a', 'abbr', 'acronym', 'b', 'code',
                      'em', 'strong']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allow_tags, strip=True))

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def from_json(json_body):
        title = json_body.get('title')
        body = json_body.get('body')
        if body is None or body == '':
            print ('error')
        return Post(title=title, body=body)

    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id, _external=True),
            'title': self.title,
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def generate_fake(count=10):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count-1)).first()
            p = Post(title=forgery_py.lorem_ipsum.sentence(),
                     body=forgery_py.lorem_ipsum.sentences(randint(1,3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def generate_title():
        from random import seed
        import forgery_py

        seed()
        posts = Post.query.all()
        for post in posts:
            if post.title is None:
                post.title = forgery_py.lorem_ipsum.sentence()
                db.session.add(post)
        db.session.commit()

    @staticmethod
    def on_body_changed(target, value, oldvalue, initiator):
        allow_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                      'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                      'h1', 'h2', 'h3', 'p', 'span', 'code', 'pre',
                      'img', 'hr', 'div']
        allow_attributes = ['src', 'alt', 'href', 'class']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html', extensions=['markdown.extensions.extra', 'markdown.extensions.codehilite']),
                                                       tags=allow_tags, attributes = allow_attributes ,strip=True))
        # target.body_html = markdown(value, output_format='html', extensions=['markdown.extensions.extra', 'markdown.extensions.codehilite'])
                                                      

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

login_manager.anonymous_user = AnonymousUser

db.event.listen(Post.body, 'set', Post.on_body_changed)
db.event.listen(Comment.body, 'set', Comment.on_body_changed)
