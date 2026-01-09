#多功能响应解析器
import json
import xml.etree.ElementTree as ET
import re
import html
from typing import Dict,List,Any,Optional,Tuple
import logging
from urllib.parse import urlparse,parse_qs,urljoin
from bs4 import BeautifulSoup
import chardet

class ResponseParse:
    """多功能响应解析器"""
    def __init__(self):
        self.logger=logging.getLogger('vuln_scanner.parser')

    def detect_content_type(self,headers:Dict,content:bytes) -> str:
        """检测响应内容类型"""
        content_type=headers.get('Content-Type').lower()

        #从Content-type判断
        if 'application/json' in content_type:
            return 'json'
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return 'xml'
        elif 'text/html' in content_type:
            return 'html'
        elif 'text/plain' in content_type:
            return 'text'
        elif 'javascript' in content_type or 'application/javascript' in content_type:
            return 'javascript'
        
        #如果无法从头判断，尝试从内容判断
        try:
            #尝试解码
            if content:
                decoded = content[:1000].decode('utf-8',errors='ignore')

                #检查是否为JSON
                decoded_stripped = decoded.strip() #移除空白字符（其他字符也可以）
                if (decoded_stripped.startswith('{') and decoded_stripped.endswith('}')) or (decoded_stripped.startswith('[') and decoded_stripped.endswith(']')):
                    try:
                        json.loads(decoded_stripped)
                        return 'json'
                    except:
                        pass

                #检查是否为XML
                if decoded_stripped.startswith('<?xml') or decoded_stripped.startswith('<'):
                    try:
                        ET.fromstring(decoded_stripped)
                        return 'xml'
                    except:
                        pass

                #检查是否为HTML
                if '<html' in decoded.lower() or '<!doctype' in decoded.lower():
                    return 'html'
            
        except Exception as e:
            self.logger.debug(f"内容类型检测失败：{e}")
        
        return 'unknown'
    
    def detect_encoding(self, content: bytes) -> str:
        """检测编码 使用chardet库检测给定的字节内容（content）的编码，如果检测成功，返回检测到的编码；如果检测失败（发生异常），则返回默认的'utf-8'"""
        try:
            result = chardet.detect(content)
            return result.get('encoding', 'utf-8')
        except:
            return 'utf-8'
    
    def parse_json(self, content: bytes) -> Dict:
        """解析JSON响应"""
        try:
            # 检测编码
            encoding = self.detect_encoding(content)
            
            # 解码并解析JSON
            decoded = content.decode(encoding, errors='ignore') #解码成字符串
            
            # 处理BOM
            if decoded.startswith('\ufeff'):
                decoded = decoded[1:]
            
            # 解析JSON
            return json.loads(decoded) #解析成json形式
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON解析失败: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"JSON解析出错: {e}")
            return {}
        
    def parse_xml(self, content: bytes) -> ET.Element:
        """解析XML响应"""
        try:
            encoding = self.detect_encoding(content)
            decoded = content.decode(encoding, errors='ignore')
            
            # 移除可能的BOM
            if decoded.startswith('\ufeff'):
                decoded = decoded[1:]
            # print(element)          # <Element 'root' at 0x...>
            # print(element.tag)      # 'root'
            # print(element[0].tag)   # 'child'
            # print(element[0].text)  # 'Text'
            return ET.fromstring(decoded) #Python 标准库中 xml.etree.ElementTree 模块的解析函数，用于将 XML 格式的字符串解析为 XML 树结构
        except ET.ParseError as e:
            self.logger.error(f"XML解析失败: {e}")
            return None
        except Exception as e:
            self.logger.error(f"XML解析出错: {e}")
            return None
        
    def parse_html(self,content:bytes) -> BeautifulSoup:
        """解析HTML响应"""
        try:
            encoding=self.detect_encoding(content)
            decoded=content.decode(encoding,errors='ignore')

            #使用BeautifulSoup解析HTML
            soup = BeautifulSoup(decoded,'html.parser')
            return soup
        except Exception as e:
            self.logger.error(f"HTML解析失败：{e}")
            return None
        
    def extract_links(self,soup:BeautifulSoup,base_url:str) -> List[str]:
        """提取HTML中的链接"""
        links=[]

        if not soup:
            return links
        
        #查找所有链接
        for tag in soup.find_all(['a','link','script','img','iframe','from']):
            url=None

            if tag.name=='a' and tag.has_attr('href'):
                url=tag['href']
            elif tag.name=='link' and tag.has_attr('href'):
                url=tag['href']
            elif tag.name=='script' and tag.has_attr('src'):
                url=tag['src']
            elif tag.name=='img' and tag.has_attr('src'):
                url=tag['src']
            elif tag.name=='iframe' and tag.has_attr('src'):
                url=tag['src']
            elif tag.name=='from' and tag.has_attr('action'):
                url=tag['action']

            if url:
                #转换相对url为绝对url
                try:
                    absolute_url=urljoin(base_url,url)
                    links.append(absolute_url)
                except:
                    pass

        return list(set(links)) #去重
    
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """从HTML中提取表单
        例子：
[
{
'action': 'http://example.com/submit',
'method': 'POST',
'enctype': 'application/x-www-form-urlencoded',
'inputs': [
{'type': 'text', 'name': 'username', 'value': '', 'required': True},
{'type': 'password', 'name': 'password', 'value': '', 'required': True},
{'type': 'select', 'name': 'country', 'options': ['China', 'USA'], 'required': False},
...
]
},
...
]
        """
        forms = []

        
        if not soup:
            return forms
        
        for form_tag in soup.find_all('form'):
            form = {
                'action': form_tag.get('action', ''),
                'method': form_tag.get('method', 'GET').upper(),
                'inputs': [],
                'enctype': form_tag.get('enctype', 'application/x-www-form-urlencoded')
            }
            
            # 提取输入字段
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                
                # 处理textarea
                if input_tag.name == 'textarea':
                    input_info['type'] = 'textarea'
                    input_info['value'] = input_tag.text
                
                # 处理select
                elif input_tag.name == 'select':
                    input_info['type'] = 'select'
                    input_info['options'] = []
                    
                    for option in input_tag.find_all('option'):
                        option_value = option.get('value', option.text)
                        input_info['options'].append(option_value)
                
                # 只添加有名称的字段
                if input_info['name']:
                    form['inputs'].append(input_info)
            
            # 构建绝对URL
            if form['action']:
                form['action'] = urljoin(base_url, form['action'])
            
            forms.append(form)
        
        return forms
    
    def extract_metadata(self,soup:BeautifulSoup) ->Dict:
        """提取HTML中的元数据"""
        metadata={
            'title':'',
            'description':'',
            'keywords':[],
            'robots':'',
            'generator':'',
            'viewport':''
        }

        if not soup:
            return metadata
        
        #提取标题
        title_tag=soup.find('title')
        if title_tag:
            metadata['title']=title_tag.text.strip()

        #提取meta标签
        for meta_tag in soup.find_all('meta'):
            name=meta_tag.get('name','').lower()
            content=meta_tag.get('content','')

            if name=='description':
                metadata['description']=content
            elif name=='keywords':
                metadata['keywords']=[k.strip() for k in content.split(',')]
            elif name=='robots':
                metadata['robots']=content
            elif name=='generator':
                metadata['generator']=content
            elif name=='viewport':
                metadata['viewport']=content

        return metadata
    
    def parse_response(self,
                       response,
                       extract_links:bool=False,
                       extract_forms:bool=False,
                       base_url:str=None) ->Dict[str,Any]:
        """解析HTML响应"""
        result={
            'status_code':getattr(response,'status_code',getattr(response,'status',0)),
            'headers':dict(getattr(response,'headers',{})),
            'url':str(getattr(response,'url','')),
            'content_type':'unknown',
            'content_length':len(getattr(response,'content',b'')),
            'parsed_content':None,
            'links':[],
            'forms':[],
            'metadata':{},
            'encoding':'utf-8'
        }

        content=getattr(response,'content',b'')

        if content:
            #检测编码
            result['encoding']=self.detect_encoding(content)

            #解析内容类型
            result['content_type']=self.detect_content_type(result['headers'],content)

            #根据类型解析内容
            if result['content_type']=='json':
                result['parsed_content']=self.parse_json(content)
            elif result['content_type']=='xml':
                result['parsed_content']=self.parse_xml(content)
            elif result['content_type']=='html':
                soup=self.parse_html(content)
                result['parsed_content']=soup

                #提取额外信息
                if soup:
                    result['metadata']=self.extract_metadata(soup)

                    if extract_links and base_url:
                        result['links']=self.extract_links(soup,base_url)

                    if extract_forms and base_url:
                        result['forms']=self.extract_forms(soup,base_url)
            else:
                #尝试作为文本处理
                try:
                    result['parsed_content']=content.decode(result['encoding'],errors='ignore')
                except:
                    result['parsed_content'] =str(content)

        return result
    
    def find_pattern(self,text:str,patterns:Dict[str,str]) ->Dict[str,List[str]]:
        """在文本中查找正则表达式模式
        patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'url': r'https?://[^\s]+',
        'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'date': r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b',
        }
        结果：
        text = 
        联系方式：
        邮箱: john.doe@example.com, 备用邮箱: JANE.DOE@EXAMPLE.COM
        电话: 123-456-7890, 555.123.4567
        网站: https://example.com 和 http://test-site.org
        服务器IP: 192.168.1.1, 10.0.0.1
        日期: 2023-12-25, 2023/12/26
        重复的邮箱: john.doe@example.com  # 这个会去重

        """
        matches={}

        for name,pattern in patterns.items():
            try:
                found=re.findall(pattern,text,re.IGNORECASE | re.MULTILINE) #忽略大小写，多行匹配
                if found:
                    matches[name] = list(set(found)) #去重
            except Exception as e:
                self.logger.warning(f"正则表达式错误{name}：{e}")

        return matches
    
    def extract_emails(self,text:str) -> List[str]:
        """提取电子邮件地址"""
        email_pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern,text)))
    
    def extract_phone_numbers(self,text:str) -> List[str]:
        """提取电话号码"""
        phone_pattern=r'(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}'
        return list(set(re.findall(phone_pattern,text)))
    
    def extract_urls(self,text:str) -> List[str]:
        """提取URL"""
        url_pattern=r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        return list(set(re.findall(url_pattern,text)))


        
            


