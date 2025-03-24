import os
import sys
import logging
import json
import time
import xml.etree.ElementTree as ET
import Evtx.Evtx as evtx
from glob import glob
import argparse
from xmljson import badgerfish as bf

logger = logging.getLogger('evtx2json')
logger.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s [%(name)10s] %(levelname)s %(message)s', datefmt='%m/%d/%y %I:%M:%S %p')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

global event_counter, error_counter

def add_splunk_handler(args):
    if args.splunk:
        try:
            from splunk_hec_handler import SplunkHecHandler
        except ModuleNotFoundError:
            logger.warning("Failed to import 'splunk_hec_handler'. Try 'pip install splunk_hec_handler'")
            return
        except Exception as err:
            logger.warning(f"Error adding Splunk handler: {err}")
            return
        
        if not args.verify:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ModuleNotFoundError:
                logger.debug("Failed to suppress SSL warnings")
        
        splunk_handler = SplunkHecHandler(
            args.host, args.token, index=args.index, port=args.port, proto=args.proto,
            ssl_verify=args.verify, source=args.source, sourcetype=args.sourcetype)
        splunk_handler.setLevel(logging.getLevelName(args.loglevel))
        logger.addHandler(splunk_handler)

def remove_namespace(tree):
    for element in tree.iter():
        if element.tag.startswith('{'):
            element.tag = element.tag.split('}')[1]
    return tree

def xml2json(xml_str):
    try:
        tree = remove_namespace(ET.fromstring(xml_str))
        return bf.data(tree)
    except Exception as err:
        logger.error(f"Failed to convert XML to JSON: {err}")
        return None

def iter_evtx2xml(evtx_file):
    global event_counter, error_counter
    error_counter = 0
    event_counter = 0
    try:
        with evtx.Evtx(evtx_file) as log:
            for record in log.records():
                event_counter += 1
                try:
                    yield record.xml()
                except Exception as err:
                    error_counter += 1
                    logger.error(f"Error parsing EVTX record: {err}")
    except Exception as err:
        logger.error(f"Failed to read EVTX file {evtx_file}: {err}")

def splunkify(output, source):
    try:
        event = output.get('Event', {})
        event['fields'] = {}
        
        if 'System' in event and 'TimeCreated' in event['System']:
            _ts = event['System']['TimeCreated'].get('@SystemTime', "")
            try:
                _ts = time.mktime(time.strptime(_ts.strip(), "%Y-%m-%d %H:%M:%S.%f"))
            except ValueError:
                _ts = time.mktime(time.strptime(_ts.strip(), "%Y-%m-%d %H:%M:%S"))
            event['fields']['time'] = _ts
        
        event['fields']['source'] = os.path.basename(source)
        if 'System' in event and 'Computer' in event['System']:
            event['fields']['host'] = event['System']['Computer']
    
        return output
    except Exception as err:
        logger.warning(f"Failed to splunkify event: {err}")
        return output

def output_stats(evtx_file, success_counter, start_time):
    delta_secs = int(time.time()) - start_time
    logger.info({'file': evtx_file, 'total_events': event_counter, 'pass': success_counter,
                 'fail': error_counter, 'time': start_time, 'elapsed_sec': delta_secs})

def process_files(args):
    if args.splunk:
        add_splunk_handler(args)
    
    start_time = int(time.time())
    for evtx_file in args.files:
        if evtx_file.endswith(".evtx"):
            logger.debug(f"Processing {evtx_file}")
            success_counter = 0
            for xml_str in iter_evtx2xml(evtx_file):
                output = xml2json(xml_str)
                if output:
                    if not args.disable_json_tweaks:
                        output = splunkify(output, evtx_file)
                    logger.info(json.dumps(output['Event']))
                    success_counter += 1
            output_stats(evtx_file, success_counter, start_time)

def process_folder(args):
    args.files = glob(os.path.join(args.folder, "*.evtx"))
    process_files(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Windows evtx files to JSON")
    parser.add_argument('--loglevel', '-v', type=int, default=20, choices=[0, 10, 20, 30, 40, 50], help="Log level")
    parser.add_argument('--disable_json_tweaks', action='store_true', help="Disable JSON tweaks")
    subparsers = parser.add_subparsers()
    
    splunk_group = parser.add_argument_group("Splunk Integration")
    splunk_group.add_argument('--splunk', action='store_true', help="Send output to Splunk")
    splunk_group.add_argument('--host', default="localhost", help="Splunk host")
    splunk_group.add_argument('--token', help="Splunk HEC Token")
    splunk_group.add_argument('--port', type=int, default=8008, help="Splunk HEC port")
    splunk_group.add_argument('--proto', choices=['http', 'https'], default='https', help="Splunk protocol")
    splunk_group.add_argument('--index', help="Splunk index")
    splunk_group.add_argument('--source', default=os.path.basename(sys.argv[0]), help="Event source")
    splunk_group.add_argument('--sourcetype', default='_json', help="Event sourcetype")
    splunk_group.add_argument('--verify', action='store_true', help="Verify SSL certificates")

    parser_fh = subparsers.add_parser('process_files')
    parser_fh.add_argument('--files', '-f', nargs='+', required=True, help="EVTX files")
    parser_fh.set_defaults(func=process_files)
    
    parser_folder = subparsers.add_parser('process_folder')
    parser_folder.add_argument('--folder', required=True, help="Folder containing EVTX files")
    parser_folder.set_defaults(func=process_folder)

    args = parser.parse_args()
    stream_handler.setLevel(logging.getLevelName(args.loglevel))
    
    try:
        args.func(args)
    except Exception as err:
        logger.error(f"Error: {err}")
        parser.print_help()
