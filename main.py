from flask import Flask, render_template, redirect, request, flash, url_for, session, send_from_directory
import fdb
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = "chave_secreta_da_turma_b"

host = "localhost"
database = r"C:\Users\Aluno\Downloads\BANCO (1)\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"


def conectar_banco():
    return fdb.connect(
        host=host,
        database=database,
        user=user,
        password=password
    )


def validar_senha(senha):

    if len(senha) < 8:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:

        if caractere.isupper():
            tem_maiuscula = True

        elif caractere.islower():
            tem_minuscula = True

        elif caractere.isdigit():
            tem_numero = True

        else:
            tem_especial = True

    return (
        tem_maiuscula
        and tem_minuscula
        and tem_numero
        and tem_especial
    )


@app.route("/")
def inicio():
    return render_template("login.html")


@app.route("/logo")
def logo():
    return send_from_directory(
        os.path.join(app.root_path, "Uploads"),
        "logo.png"
    )


@app.route("/fundo")
def fundo():
    return send_from_directory(
        os.path.join(app.root_path, "Uploads"),
        "fundo.png"
    )


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():

    if request.method == "POST":

        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")

        if not nome or not email or not senha:
            flash("Preencha todos os campos.")
            return render_template("cadastro_usuario.html")

        if not validar_senha(senha):
            flash(
                "A senha deve ter no mínimo 8 caracteres, "
                "uma letra maiúscula, uma letra minúscula, "
                "um número e um caractere especial."
            )
            return render_template("cadastro_usuario.html")

        conexao = None
        cursor = None

        try:

            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                """
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE EMAIL = ?
                """,
                (email,)
            )

            usuario_existente = cursor.fetchone()

            if usuario_existente:
                flash("Este e-mail já está cadastrado.")
                return render_template("cadastro_usuario.html")

            senha_criptografada = generate_password_hash(senha)

            cursor.execute(
                """
                INSERT INTO USUARIO
                (
                    NOME,
                    EMAIL,
                    SENHA,
                    TIPO,
                    ATIVO,
                    TENTATIVAS_LOGIN,
                    BLOQUEADO
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?,
                    ?
                )
                """,
                (
                    nome,
                    email,
                    senha_criptografada,
                    1,
                    True,
                    0,
                    False
                )
            )

            conexao.commit()

            cursor.execute(
                """
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE EMAIL = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                raise Exception(
                    "Usuário não foi encontrado após o cadastro."
                )

            id_usuario = usuario[0]

            cursor.execute(
                """
                INSERT INTO HISTORICO_SENHA
                (
                    SENHA,
                    ID_USUARIO,
                    DATA_ALTERACAO
                )
                VALUES
                (
                    ?,
                    ?,
                    CURRENT_TIMESTAMP
                )
                """,
                (
                    senha_criptografada,
                    id_usuario
                )
            )

            conexao.commit()

            flash("Cadastro realizado com sucesso!")

            return redirect(url_for("inicio"))

        except Exception as erro:

            if conexao:
                conexao.rollback()

            print("ERRO AO SALVAR CADASTRO:")
            print(erro)

            flash("Erro ao salvar o cadastro.")

            return render_template("cadastro_usuario.html")

        finally:

            if cursor:
                cursor.close()

            if conexao:
                conexao.close()

    return render_template("cadastro_usuario.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")

        if email == "" or senha == "":
            flash("Preencha o e-mail e a senha.")
            return render_template("login.html")

        conexao = None
        cursor = None

        try:

            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                """
                SELECT
                    ID_USUARIO,
                    NOME,
                    EMAIL,
                    SENHA,
                    TIPO,
                    ATIVO,
                    TENTATIVAS_LOGIN,
                    BLOQUEADO
                FROM USUARIO
                WHERE EMAIL = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            if usuario is None:
                flash("E-mail ou senha incorretos.")
                return render_template("login.html")

            id_usuario = usuario[0]
            nome_usuario = usuario[1]
            email_usuario = usuario[2]
            senha_banco = usuario[3]
            tipo_usuario = usuario[4]
            ativo = usuario[5]
            tentativas_login = usuario[6]
            bloqueado = usuario[7]

            if isinstance(tentativas_login, str):
                tentativas_login = int(tentativas_login)

            if ativo is False or ativo == 0:
                flash(
                    "Sua conta está inativa. "
                    "Não é possível realizar o login."
                )
                return render_template("login.html")

            if bloqueado is True or bloqueado == 1:
                flash(
                    "Sua conta está bloqueada por excesso de tentativas."
                )
                return render_template("login.html")

            if not senha_banco:
                flash("Este usuário não possui uma senha cadastrada.")
                return render_template("login.html")

            senha_correta = check_password_hash(
                senha_banco,
                senha
            )

            if not senha_correta:

                tentativas_login += 1

                if tentativas_login >= 3:

                    cursor.execute(
                        """
                        UPDATE USUARIO
                        SET
                            TENTATIVAS_LOGIN = ?,
                            BLOQUEADO = ?
                        WHERE ID_USUARIO = ?
                        """,
                        (
                            tentativas_login,
                            True,
                            id_usuario
                        )
                    )

                    conexao.commit()

                    flash(
                        "Você atingiu o limite de 3 tentativas. "
                        "Sua conta foi bloqueada."
                    )

                    return render_template("login.html")

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET TENTATIVAS_LOGIN = ?
                    WHERE ID_USUARIO = ?
                    """,
                    (
                        tentativas_login,
                        id_usuario
                    )
                )

                conexao.commit()

                tentativas_restantes = 3 - tentativas_login

                if tentativas_restantes == 1:

                    flash(
                        "E-mail ou senha incorretos. "
                        "Atenção: você tem apenas 1 tentativa restante. "
                        "Depois disso, sua conta será bloqueada."
                    )

                else:

                    flash(
                        "E-mail ou senha incorretos. "
                        "Você ainda possui "
                        + str(tentativas_restantes)
                        + " tentativas."
                    )

                return render_template("login.html")

            cursor.execute(
                """
                UPDATE USUARIO
                SET
                    TENTATIVAS_LOGIN = ?,
                    BLOQUEADO = ?
                WHERE ID_USUARIO = ?
                """,
                (
                    0,
                    False,
                    id_usuario
                )
            )

            conexao.commit()

            session.clear()

            session["usuario_id"] = id_usuario
            session["usuario_nome"] = nome_usuario
            session["usuario_email"] = email_usuario
            session["usuario_tipo"] = tipo_usuario

            print("LOGIN CORRETO - REDIRECIONANDO")

            return redirect(url_for("sucesso"))

        except Exception as erro:

            print("ERRO NO LOGIN:")
            print(erro)

            flash("Erro ao realizar o login.")

            return render_template("login.html")

        finally:

            if cursor:
                cursor.close()

            if conexao:
                conexao.close()

    return render_template("login.html")


@app.route("/sucesso")
def sucesso():

    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return render_template("sucesso.html")


@app.route("/sistema")
def sistema():

    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return render_template("sistema.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("inicio"))


@app.route("/teste-banco")
def teste_banco():

    conexao = None
    cursor = None

    try:

        conexao = conectar_banco()
        cursor = conexao.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM USUARIO"
        )

        quantidade = cursor.fetchone()[0]

        return (
            "Banco funcionando! "
            "Usuários cadastrados: "
            + str(quantidade)
        )

    except Exception as erro:

        return "ERRO NO BANCO: " + str(erro)

    finally:

        if cursor:
            cursor.close()

        if conexao:
            conexao.close()


if __name__ == "__main__":
    app.run(debug=True)