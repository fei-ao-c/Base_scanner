#请求构造器
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlencode,quote
from typing import Dict,List,Any,Optional,Union
import logging

class RequestBuilder:
    """请求构造器，支持多种数据格式"""
    def __init__(self):
        self.logger=logging.getLogger('vuln_scanner.builder')
    
    def build_from_data(self,data:Dict[str,Any]) ->Dict[str,str]:
        """构建表单结果"""
        from_data={}

        for key,value in data.items():
            if isinstance(value,(list,tuple)):
                #处理数组（如checkbox）
                from_data[key]=','.join(str(v) for v in value)
            elif isinstance(value,bool):
                from_data[key]='1' if value else '0'
            else:
                from_data[key]=str(value)

        return from_data
    def build_multipart_data(self,data:Dict[str,Any],files: Dict[str, Any] = None) ->tuple:
        """构建multipart/form-data请求数据"""
        from io import BytesIO
        boundary='---WebkitFormBoundary' + ''.join([str(i) for i in range(10) for _ in range(5)])
        body_parts=[]

        #添加表单字段
        for key,value in data.items():
            body_parts.append(f'--{boundary}')
            body_parts.append(f'Content-Disposition: form-data; name="{key}"')
            body_parts.append('')
            body_parts.append(str(value))

        #添加文件
        if files:
            for field_name,file_info in files.items():
                if isinstance(file_info,tuple):
                    filename,content,content_type=file_info
                else:
                    filename='file.txt'
                    content=file_info
                    content_type='application/octet-stream'

                body_parts.append(f'--{boundary}')
                body_parts.append(
                    f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
                )
                body_parts.append(f'Content-Type: {content_type}')
                body_parts.append('')

                if isinstance(content,str):
                    body_parts.append(content)
                else:
                    body_parts.append(content.decode('utf-8',errors='ignore'))
        body_parts.append(f'--{boundary}--')
        body_parts.append('')

        body='\r\n'.join(body_parts)

        headers={
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        }

        return headers,body
    
    def build_json_data(self,data:Any) ->str:
        """构建json请求数据"""
        return json.dumps(data,ensure_ascii=False)
    def build_xml_data(self,root_tag:str,data:Dict[str,Any]) ->str:
        """构建xml请求数据"""
        root=ET.Element(root_tag)

        def add_elements(parent,data): #递归添加xml元素
            if isinstance(data,dict):
                for key,value in data.items():
                    if isinstance(value,(dict,list)):
                        child=ET.SubElement(parent,key)
                        add_elements(child,value)
                    else:
                        child=ET.SubElement(parent,key)
                        child.text=str(value)
            elif isinstance(data,list):
                for item in data:
                    add_elements(parent,item)
        add_elements(root,data)

        return ET.tostring(root,encoding='unicode',method='xml')

    def build_soap_request(self,action:str,parameters:Dict[str,Any]) ->str:
        """构建soap请求数据"""
        soap_template="""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Body>
    <{action} xmlns="http://tempuri.org/">
      {parameters}
    </{action}>
  </soap:Body>
</soap:Envelope>"""    

        param_elements=[]
        for key,value in parameters.items():
            param_elements.append(f'<{key}>{value}</{key}>')

        parameters_xml='\n   '.join(param_elements)

        return soap_template.format(action=action,parameters=parameters_xml)
    
    def build_graphql_query(self,query:str,variables:Dict=None,operation_name:str=None) ->Dict:
        """构建graphql查询"""
        payload={'query':query}

        if variables:
            payload['variables']=variables

        if operation_name:
            payload['operationName']=operation_name

        return payload
    
    def build_url_with_params(self,base_url:str,params:Dict[str,Any]) ->str:
        """构建带查询参数的url"""
        if not params:
            return base_url
        
        query_string=urlencode(params,doseq=True,quote_via=quote)

        #检查url中是否已经有查询参数
        separtor='&' if '?' in base_url else '?'

        return f'{base_url}{separtor}{query_string}'
    
    def build_custom_headers(self,
                             content_type:str=None,
                             accept:str=None,
                             authorization:str=None,
                             custom_headers:Dict[str,str]=None) ->Dict[str,str]:
        """构建自定义请求头"""
        headers={}
        if content_type:
            headers['Content-Type']=content_type
        if accept:
            headers['Accept']=accept
        if authorization:
            headers['Authorization']=authorization
        if custom_headers:
            headers.update(custom_headers)
        return headers
    