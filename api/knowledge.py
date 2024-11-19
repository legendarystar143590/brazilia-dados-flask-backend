from flask import Blueprint, request, jsonify, current_app, url_for
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from models import DocumentKnowledge, Website, Text, KnowledgeBase, Bot, User, BillingPlan
from langchain_community.document_loaders import PyMuPDFLoader
from langchain_community.document_loaders import Docx2txtLoader
from langchain_community.document_loaders import TextLoader
from utils.provider import generate_kb_from_document, generate_kb_from_url,  tiktoken_text_split, tiktoken_doc_split 
from utils.scraper import scrape_url
from utils.vectorizor import delDocument, delKnowledgeBase
from utils.common import get_url_from_name
import uuid
import os
from werkzeug.utils import secure_filename
import json
from datetime import datetime

knowledge_blueprint = Blueprint('lknowledge_blueprintueprint', __name__)

@knowledge_blueprint.route('/upload_document', methods=['POST'])
@jwt_required()
def upload_document():
    try:
        name = request.form['name']
        files = request.files.getlist('files')
        qas_json = request.form['qa']
        docs_json = request.form['docs']
        urls_json = request.form['urls']
        user_id = request.form["userID"]
        if name is None or user_id is None:
            return jsonify({"error":"Unauthorized request!"}), 405
        print("name >>>", name)
        print("files >>>", len(files))
        print("qas >>>", urls_json)

        new_unique_id = str(uuid.uuid4())
        doc_storage = 0

        #  Check limits
        for file in files:
            # Process each file (e.g., saving or using it)
            file.save('uploads/' + file.filename)
            file_path = 'uploads/' + file.filename
            filename = file.filename
            filesize_byte = os.path.getsize(file_path)/1024
            doc_storage = doc_storage + filesize_byte / 1024
        user = User.get_by_userID(user_id)
        billing_plan = BillingPlan.get_by_code(user.billing_plan)
        max_storage = billing_plan.max_storage
        knowledge_bases = KnowledgeBase.query.filter_by(user_id=user.id).all()
        current_storage = 0
        for knowledge_base in knowledge_bases:
            unique_id = knowledge_base.unique_id
            print("unique_id -->", unique_id)
            docs = DocumentKnowledge.query.filter_by(unique_id=unique_id).all()
            for doc in docs:
                size = doc.file_size_mb if doc.file_size_mb is not None else 0
                current_storage = current_storage + size
        # doc_storage = doc_storage + current_storage
        print("max_storage -->", max_storage)
        print("current_storage -->", current_storage)
        print("doc_storage -->", doc_storage)
        if max_storage < current_storage + doc_storage:
            for file in files:
                file_path = 'uploads/' + file.filename
                if os.path.exists(file_path):
                    os.remove(file_path)
                    # print(f"Deleted file: {file_path}")
                else:
                    print("The file does not exist:")
            return jsonify({'error': 'Exceeds Max Storage'}), 403
            
        bad_urls =[]
        if urls_json:
            urls = json.loads(urls_json)
            for url in urls:
                print(url['url'])
                text = scrape_url(url["url"])
                if (text == False):
                    bad_urls.append(url["url"])
                    continue
                new_website = Website(url=url["url"], unique_id=new_unique_id, created_at=url['created_at'])
                new_website.save()
                # save_from_url(new_website.id, url)
                print(new_website.id)
                
                chunks = tiktoken_text_split(text)
                type_of_knowledge = 'url'
                print("website >>>", chunks)

                generate_kb_from_url(chunks, new_unique_id, new_website.id, type_of_knowledge)

        new_docs = json.loads(docs_json)
        i = 0
        for file in files:
            file_path = 'uploads/' + file.filename
            filename = file.filename
            filesize_byte = os.path.getsize(file_path)/1024
            print(filesize_byte)
            filesize = ''
            if filesize_byte > 512:
                filesize = f"{float(filesize_byte/1024):.2f} MB"
            else:
                filesize = f"{float(filesize_byte):.2f} KB"
            extension = os.path.splitext(secure_filename(file.filename))[1]
            loader = None
            
            type_of_knowledge = 'pdf'
            # print("extension is >>>>", extension)
            if extension.lower() == ".pdf":
                loader = PyMuPDFLoader(file_path)
            elif extension.lower() == ".txt":
                type_of_knowledge = 'txt'
                loader = TextLoader(file_path, encoding='utf-8')
            elif extension.lower() == ".docx" or extension.lower() == ".doc":
                type_of_knowledge = 'docx'
                loader = Docx2txtLoader(file_path)
            data = loader.load()

            chunks = tiktoken_doc_split(data)
            created_at = new_docs[i]['created_at']
            new_doc = DocumentKnowledge(filename=filename, type=extension, file_size=filesize, file_size_mb=filesize_byte/1024,unique_id=new_unique_id, created_at=created_at)
            new_doc.save()
            generate_kb_from_document(chunks, new_unique_id, new_doc.id, type_of_knowledge)
            doc_storage = float(doc_storage) + filesize_byte/1024
            # After processing is done, delete the file
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")
            else:
                print(f"The file does not exist: {file_path}")
                print("Doc ID >>> ", new_doc.id)
            i += 1

        if qas_json:
            qas = json.loads(qas_json)
            for qa in qas:
                new_qa = Text(question=qa["question"], answer=qa["answer"], unique_id=new_unique_id)
                new_qa.save()
                text = f"Question: {qa['question']} Answer: {qa['answer']}"
                chunks = tiktoken_text_split(text)
                type_of_knowledge = 'qa'
                generate_kb_from_url(chunks, new_unique_id, new_qa.id, type_of_knowledge)

                print("QA ID>>>", new_qa.id)
        new_knowledge = KnowledgeBase(name=name, unique_id=new_unique_id, user_id=user_id)
        new_knowledge.save()
        url_res = len(bad_urls)==0
        new_knowledge_base = KnowledgeBase.query.filter_by(unique_id=new_unique_id).first()
        new_base_id = new_knowledge_base.id
        return {'status': 'success', 'message': f'Received {len(files)} files with name {name}', 'bad_url':url_res, 'base_id':new_base_id}
    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Error saving database!'}), 500

@knowledge_blueprint.route('/get_knowledge_bases',methods=['GET'])
@jwt_required()
def get_knowledgebases():
    try:
        user_id = request.args.get('userId')
        print("GOT it>>>")
        print(user_id)
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        bases = KnowledgeBase.query.filter_by(user_id=user_id).all()
        bases_list = []
        for base in bases:
            avatars = []
            base_json = base.json()
            bots = Bot.query.filter_by(knowledge_base=base.unique_id).all()
            print(bots)
            base_json['bot_avatar'] = []
            base_json['bot_names'] = []
            if bots:
                for bot in bots:
                    base_json['bot_names'].append(bot.name)
                    if bot.avatar:
                        avatarUrl = get_url_from_name(bot.avatar)
                        base_json['bot_avatar'].append(avatarUrl)
                    else:
                        base_json['bot_avatar'].append('')

            bases_list.append(base_json)
        return jsonify(bases_list), 200
    except ValueError:
        # If the provided user_id cannot be converted to an integer, return an error
        return jsonify({'error': 'Invalid user_id format. It should be an integer.'}), 400

@knowledge_blueprint.route('/get_knowledge_base',methods=['GET'])
@jwt_required()
def get_knowledgebase():
    try:
        baseId = request.args.get('baseId')
        print("GOT it>>>")
        print(baseId)
        if not baseId:
            return jsonify({'error': 'baseId is required'}), 400

        base = KnowledgeBase.query.filter_by(id=baseId).first()
        websites = Website.query.filter_by(unique_id=base.unique_id).all()
        websites_list = [website.json() for website in websites]
        docs = DocumentKnowledge.query.filter_by(unique_id=base.unique_id).all()
        docs_list = [doc.json() for doc in docs]
        print(docs_list)
        texts = Text.query.filter_by(unique_id=base.unique_id).all()
        texts_list = [text.json() for text in texts]
        # Construct the response data dictionary
        data = {
            'base': base.json() if base else None,
            'websites': websites_list,
            'documents': docs_list,
            'texts': texts_list,
        }

        return jsonify(data), 200

    except Exception as e:
        # Handle exceptions properly too
        return jsonify({'error': str(e)}), 500

@knowledge_blueprint.route('/update_knowledge_base', methods=['POST'])
@jwt_required()
def update_knowledge_base():
    try:
        unique_id = request.form.get('unique_id')
        print("unique_id >>> ", unique_id)
        # Retrieve the existing knowledge base entry using the provided unique_id
        knowledge_base_entry = KnowledgeBase.query.filter_by(unique_id=unique_id).first()
        if not knowledge_base_entry:
            return jsonify({"error": "Knowledge base entry not found."}), 404
       
        # Extract the relevant information from the form
        name = request.form.get('name')
        files = request.files.getlist('files')
        docs_json = request.form.get('docs')
        qas_json = request.form.get('qa')
        urls_json = request.form.get('urls')
        user_id = request.form.get("userID")
        print("Requested Form data >>>>>", request.form)
        if user_id is None:
            return jsonify({"error": "Unauthorized request!"}), 405

        doc_storage = 0

        #  Check limits
        for file in files:
            # Process each file (e.g., saving or using it)
            file.save('uploads/' + file.filename)
            file_path = 'uploads/' + file.filename
            filename = file.filename
            filesize_byte = os.path.getsize(file_path)/1024
            doc_storage = doc_storage + filesize_byte / 1024
        user = User.get_by_userID(user_id)
        billing_plan = BillingPlan.get_by_code(user.billing_plan)
        max_storage = billing_plan.max_storage
        knowledge_bases = KnowledgeBase.query.filter_by(user_id=user.id).all()
        current_storage = 0
        for knowledge_base in knowledge_bases:
            current_doc_unique_id = knowledge_base.unique_id
            docs = DocumentKnowledge.query.filter_by(unique_id=current_doc_unique_id).all()
            for doc in docs:
                size = doc.file_size_mb if doc.file_size_mb else 0
                print(size)
                current_storage = current_storage + size
        print("max_storage -->", max_storage)
        print("current_storage -->", current_storage)
        print("doc_storage -->", doc_storage)
        if max_storage < current_storage + doc_storage:
            print("Exceeds Max Storage -->", max_storage, current_storage, doc_storage)
            for file in files:
                file_path = 'uploads/' + file.filename
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                else:
                    print(f"The file does not exist: {file_path}")
            return jsonify({'error': 'Exceeds Max Storage'}), 403

        if name:
            knowledge_base_entry.name = name
            knowledge_base_entry.save()
        bad_urls = []
        # Process URLs JSON if provided
        print("urls_json", urls_json)
        if urls_json:
            urls = json.loads(urls_json)
            for url in urls:
                # print(url['id'])
                # if len(urls) > 0 and url['id'] != -1:
                #     continue
                print("Created_at: ", url['created_at'])
                new_website = Website(url=url['url'], unique_id=unique_id, created_at=url['created_at'])
                new_website.save()
                # save_from_url(new_website.id, url)
                print(new_website.id)
                text = scrape_url(url['url'])
                if (text == False):
                    bad_urls.append(url["url"])
                    continue
                chunks = tiktoken_text_split(text)
                type_of_knowledge = 'url'
                generate_kb_from_url(chunks, unique_id, new_website.id, type_of_knowledge)
                      
        # Process uploaded files
        if len(files) > 0:
            new_docs = json.loads(docs_json)
            i = 0
            for file in files:
                file_path = 'uploads/' + file.filename
                filename = file.filename
                filesize_byte = os.path.getsize(file_path)/1024
                # print(filesize)
                filesize = ''
                if filesize_byte > 512:
                    filesize = f"{(filesize_byte/1024):.2f} MB"
                else:
                    filesize = f"{filesize_byte:.2f} KB"
                extension = os.path.splitext(secure_filename(file.filename))[1]
                loader = None
                type_of_knowledge = ''
                # print("extension is >>>>", extension)
                if extension.lower() == ".pdf":
                    type_of_knowledge = "pdf"
                    loader = PyMuPDFLoader(file_path)
                elif extension.lower() == ".txt":
                    type_of_knowledge = "txt"
                    loader = TextLoader(file_path, encoding='utf-8')
                elif extension.lower() == ".docx":
                    type_of_knowledge = "docx"
                    print(type_of_knowledge)
                    loader = Docx2txtLoader(file_path)
                data = loader.load()

                chunks = tiktoken_doc_split(data)
                created_at = new_docs[i]['created_at']
                print("created_at timestamp:", created_at)
                new_doc = DocumentKnowledge(filename=filename, file_size=filesize, file_size_mb=filesize_byte/1024,  type=extension, unique_id=unique_id, created_at=created_at)
                i += 1
                new_doc.save()
                generate_kb_from_document(chunks, unique_id, new_doc.id, type_of_knowledge)
                
                # After processing is done, delete the file
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                else:
                    print(f"The file does not exist: {file_path}")
                    print("Doc ID >>> ", new_doc.id)
            
        # Process Q&As if provided
        if qas_json:
            qas = json.loads(qas_json)
            print(qas)
            for qa in qas:
                if qa.get('id') is None:
                    new_qa = Text(question=qa["question"], answer=qa["answer"], unique_id=unique_id)
                    new_qa.save()
                    text = f"Question: {qa['question']} Answer: {qa['answer']}"
                    chunks = tiktoken_text_split(text)
                    type_of_knowledge = 'qa'
                    generate_kb_from_url(chunks, unique_id, new_qa.id, type_of_knowledge)
        url_res = len(bad_urls) == 0
        
        return jsonify({'status': 'success', 'message': f'Updated knowledge base entry with unique_id {unique_id}', 'bad_url':url_res})
    except Exception as e:
        print("Error: ", str(e))
        return jsonify({'status':'error'}), 500

@knowledge_blueprint.route('/del_document', methods=['POST'])
@jwt_required()       
def del_document():
    data = request.get_json()
    doc_id = data["id"]
    if not doc_id:
        return jsonify({'status': 'error'}), 500
    document = DocumentKnowledge.get_by_id(doc_id)
    if delDocument(document.unique_id, document.id, document.type[1:]):
        DocumentKnowledge.del_by_id(doc_id)
        return jsonify({'status': 'success'}), 201
    else:
        return jsonify({'status':'error'}), 500

@knowledge_blueprint.route('/del_url', methods=['POST'])
@jwt_required()       
def del_website():
    data = request.get_json()
    website_id = data["id"]
    website = Website.get_by_id(website_id)
    if delDocument(website.unique_id, website.id, "url"):
        Website.del_by_id(website_id)
        return jsonify({'status': 'success'}), 201
    else:
        return jsonify({'status': 'error'}), 500

@knowledge_blueprint.route('/del_text', methods=['POST'])
@jwt_required()       
def del_text():
    data = request.get_json()
    qu_id = data["id"]
    if not qu_id:
        return jsonify({'status': 'error'}), 500
    text = Text.get_by_id(qu_id)
    if delDocument(text.unique_id, text.id, "text"):
        Text.del_by_id(qu_id)
        return jsonify({'status': 'success'}), 201
    else:
        return jsonify({'status':'error'}), 500
        
@knowledge_blueprint.route('/del_knowledgebase', methods=['POST'])
@jwt_required()       
def del_knowledgebase():
    data = request.get_json()
    id = data["baseId"]
    kb = KnowledgeBase.get_by_id(id)
    unique_id = kb.unique_id
    bot = Bot.query.filter_by(knowledge_base=unique_id).first()
    if bot:
        return jsonify({'status':'exist'}), 400
    elif delKnowledgeBase(kb.unique_id):
        KnowledgeBase.delete_by_id(id)
        return jsonify({'status': 'success'}), 201
    else:
        return jsonify({'status':'error'}), 500