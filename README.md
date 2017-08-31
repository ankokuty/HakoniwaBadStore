# はじめに
箱庭BadStoreは、Kurt Roemer 氏によって開発されたBadStore(http://www.badstore.net 現在はアクセスできない)を、Burp Suiteの拡張として動作するよう書き直したものです。

Burp Suite Japan User Groupの初心者向け[ハンズオンイベント](https://connpass.com/event/56013/)では、BadStoreを題材として利用しました。
オリジナルのBadStoreはisoイメージとして配布されており、実行するには仮想マシンなどからCDブートする必要があります。イベントにおいて、仮想マシンとの通信がうまくできない人が少なからずいたため、より通信トラブルが少なくなることを目的として作成しました。

# ダウンロード
[HakoniwaBadStore.jar](https://github.com/ankokuty/HakoniwaBadStore/blob/master/dist/HakoniwaBadStore.jar?raw=true)

# 注意
箱庭BadStoreは、デモやセキュリティトレーニング目的のみで利用されることを想定している、脆弱性を意図的に作り込んだセキュアではないプログラムです。
利用によって何らかの損害が生じた場合でも一切責任を負えませんので、自己責任でご利用ください。

# オリジナルとの相違点
- [DB]
オリジナルではデータベースとしてMySQLが使われていましたが、箱庭BadStoreではSQLiteを使用しています。

- [httpd]
オリジナルではApache HTTP Server が使われていましたが、箱庭BadStoreではEclipse Vert.x を内包してHTTPを処理しています。

- [名前解決]
オリジナルは/etc/hostsファイルを更新するなどによりwww.badstore.netの名前解決をする必要がありましたが、箱庭BadStoreではこの手順を不要にしました。

- [言語]
オリジナルはPerlで書かれていましたが、箱庭BadStoreはBurp Suiteの拡張にするためにJavaで書いています。

- [コマンドインジェクション]
オリジナルにはperlのopen関数利用によるコマンドインジェクションがありましたが、Perl固有の問題であるため箱庭BadStoreでは実装していません。

- [その他]
サプライヤー機能については、まだ実装できていません。

# ライセンス
GNU GPL v2.0 またはそれ以降

# 箱庭BadStoreが利用している外部のライブラリ
- [Burp Extender API](https://github.com/PortSwigger/burp-extender-api) Burp Suite Professional Licence
- [Eclipse Vert.x](http://vertx.io/) Eclipse Public License 1.0 とApache License 2.0 のデュアルライセンス
- [SQLite JDBC Driver](https://github.com/xerial/sqlite-jdbc) Apache License version 2.0
