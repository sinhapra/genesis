import pathlib, tempfile, subprocess, time, hashlib, json
ns = {'__name__': 'benchmark_helpers'}
text = pathlib.Path('tests/integration.py').read_text(encoding='utf-8-sig')
import sys
sys.argv = ['benchmark', './ufcp']
exec(text[:text.index('def transfer(')], ns)
results=[]
with tempfile.TemporaryDirectory(prefix='ufcp-benchmark-') as td:
    root=pathlib.Path(td)
    for size, delay in [(4*1024*1024, .1)]:
        source=root/'source.bin'
        with source.open('wb') as f:
            block=bytes(range(256))*4096
            for _ in range(size//len(block)): f.write(block)
        expected=hashlib.sha256(source.read_bytes()).hexdigest()
        for window, capacity in [(32,64),(256,256)]:
            target=root/f'out-{size}-{window}'
            port=ns['free_port']()
            recv=subprocess.Popen(['./ufcp','recv','127.0.0.1',str(port),str(target),f'--receive-chunks={capacity}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            relay=None
            try:
                assert recv.stdout.readline().startswith('Listening')
                sendport=port
                if delay:
                    relay=ns['Relay'](port,None,size,delay)
                    sendport=relay.socket.getsockname()[1]
                start=time.monotonic()
                sent=subprocess.run(['./ufcp','send','127.0.0.1',str(sendport),str(source),'--cc=bbr-inspired',f'--window={window}'],capture_output=True,text=True,timeout=240)
                elapsed=time.monotonic()-start
                assert sent.returncode==0, sent.stderr
                out,err=recv.communicate(timeout=10)
                assert recv.returncode==0,err
                digest=hashlib.sha256(target.read_bytes()).hexdigest()
                assert digest==expected
                row=dict(bytes=size,added_rtt_ms=delay*2000,window=window,receive_chunks=capacity,seconds=round(elapsed,3),MiB_s=round(size/elapsed/1048576,3),sha256_match=True,sender=sent.stdout.strip())
                results.append(row)
                print(json.dumps(row),flush=True)
                pathlib.Path('benchmark-tuned-results.json').write_text(json.dumps(results,indent=2)+'\n')
                target.unlink()
            finally:
                if relay: relay.close()
                if recv.poll() is None:
                    recv.kill(); recv.communicate()



