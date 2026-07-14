"""
Automated Traffic Collection Script
Complete version with sysdig functionality enabled
"""

import logging
import sys
import time
import signal
import requests
import subprocess
import argparse
from pathlib import Path

logger = logging.getLogger(__name__)


class TrafficCollector:
    def __init__(self, cve, normal_time: int = 60, malicious_time: int = 20):
        self.cve = cve
        self.project_dir = Path(__file__).parent.parent
        self.data_dir = cve.data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.script_dir = cve.env_dir.parent
        self.port = cve.port

        # Run time settings (in seconds)
        self.normal_time = normal_time
        self.malicious_time = malicious_time

        # Process tracking
        self.sysdig_process = None
        self.locust_process = None
        
        # Setup signal handling
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)

    def cleanup(self, signum=None, frame=None):
        """Clean up all running processes"""
        logger.info("Cleaning up processes...")

        if self.locust_process and self.locust_process.poll() is None:
            logger.info("Stopping locust process...")
            self.locust_process.terminate()
            try:
                self.locust_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.locust_process.kill()

        if self.sysdig_process and self.sysdig_process.poll() is None:
            logger.info("Stopping sysdig process...")
            self.sysdig_process.terminate()
            try:
                self.sysdig_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.sysdig_process.kill()

        logger.info("Cleanup completed")
        if signum:
            sys.exit(1)
    
    def start_capture(self, capture_file):
        """Start sysdig capture"""
        logger.info(f"Starting sysdig capture: {capture_file.name}")

        try:
            self.sysdig_process = subprocess.Popen(
                ['sudo', 'sysdig', '-s', '10000', '-w', str(capture_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )

            logger.info("Waiting 3 seconds for sysdig to initialize...")
            time.sleep(3)

            # Verify sysdig is still running
            if self.sysdig_process.poll() is not None:
                logger.error("sysdig process exited early")
                return False

            logger.info("Sysdig capture started successfully")
            return True

        except Exception as e:
            logger.error(f"Error starting sysdig: {e}")
            return False
    
    def stop_capture(self):
        """Stop sysdig capture"""
        logger.info("Stopping sysdig capture")

        if self.sysdig_process and self.sysdig_process.poll() is None:
            try:
                result = subprocess.run(['sudo', 'killall', 'sysdig'],
                                        capture_output=True, timeout=5)
                self.sysdig_process.wait(timeout=5)

                if result.returncode == 0:
                    logger.info("Sysdig stopped")
                else:
                    # killall may return non-zero if process already terminated
                    logger.info("Sysdig process may have already terminated")

                return True

            except subprocess.TimeoutExpired:
                # Force kill with SIGKILL if still running
                logger.warning("Force killing sysdig with SIGKILL...")
                subprocess.run(['sudo', 'killall', '-9', 'sysdig'],
                               capture_output=True)
                try:
                    self.sysdig_process.wait(timeout=2)
                except:
                    pass
                logger.info("Sysdig force stopped")
                return True
        else:
            logger.info("Sysdig process not running")
        return True
    
    def execute_traffic(self, traffic_type):
        """Execute locust traffic generation"""
        logger.info(f"Executing {traffic_type} operation...")

        # Check if traffic script exists
        traffic_script = self.script_dir / f"{traffic_type}.py"
        if not traffic_script.exists():
            logger.error(f"Traffic script not found: {traffic_script}")
            return False

        # Set run time based on traffic type
        if traffic_type == 'normal':
            run_time = f'{self.normal_time}s'
        else:
            run_time = f'{self.malicious_time}s'

        # Prepare locust command
        cmd = [
            'locust',
            '-f', str(traffic_script),
            '--headless',
            '--users', '1',
            '--spawn-rate', '1',
            '--run-time', run_time,
            '--host', f'http://localhost:{self.port}'
        ]

        try:
            logger.info("Starting locust...")
            self.locust_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Monitor output in real-time
            while True:
                output = self.locust_process.stdout.readline()
                if output == '' and self.locust_process.poll() is not None:
                    break
                if output:
                    logger.info(output.strip())

            # Wait for completion with timeout (run_time + buffer)
            if traffic_type == 'normal':
                timeout = self.normal_time + 140
            else:
                timeout = self.malicious_time + 30
            try:
                return_code = self.locust_process.wait(timeout=timeout)

                if return_code == 0:
                    logger.info(f"{traffic_type} operation completed successfully")
                    return True
                else:
                    logger.error(f"{traffic_type} operation failed with code {return_code}")
                    return False

            except subprocess.TimeoutExpired:
                logger.warning("Locust timeout, terminating...")
                self.locust_process.kill()
                return False
        except Exception as e:
            logger.error(f"Error running locust: {e}")
            return False
        finally:
            self.locust_process = None
    
    def collect_single(self, traffic_type):
        """Collect traffic for one type"""
        logger.info(f"=== Collecting {traffic_type} traffic ===")

        capture_file = self.data_dir / f"{traffic_type}.scap"

        # Remove existing capture file if it exists
        if capture_file.exists():
            logger.info(f"Removing existing capture file: {capture_file.name}")
            capture_file.unlink()

        try:
            # Step 1: Start capture
            if not self.start_capture(capture_file):
                logger.error("Failed to start sysdig capture")
                return False

            # Step 2: Execute traffic
            if not self.execute_traffic(traffic_type):
                logger.error("Failed to execute traffic generation")
                self.stop_capture()
                return False

            # Step 3: Stop capture
            if not self.stop_capture():
                logger.warning("Issues stopping capture")

            logger.info(f"=== {traffic_type} traffic collection completed ===")
            return True

        except Exception as e:
            logger.error(f"Error in collection: {e}")
            self.cleanup()
            return False
    
    def preflight_checks(self):
        """Run comprehensive checks before starting"""
        logger.info("Running preflight checks...")

        # Check locust
        try:
            result = subprocess.run(['locust', '--version'],
                                    capture_output=True, check=True, text=True)
            logger.info(f"Locust version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("locust not found or not working")
            return False

        # Check sysdig
        try:
            result = subprocess.run(['sudo', 'sysdig', '--version'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Sysdig is available")
            else:
                logger.warning("sysdig may not be properly installed")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("sysdig not found or not responding")
            return False

        # Check target service
        try:
            response = requests.get(f'http://localhost:{self.port}', timeout=5)
            logger.info(f"Target service responding (status: {response.status_code})")
        except ImportError:
            logger.warning("requests module not available for service check")
        except Exception:
            logger.warning(f"Target service may not be running on localhost:{self.port}")

        # Check sudo permissions for sysdig
        try:
            result = subprocess.run(['sudo', '-n', 'true'],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info("Sudo permissions available")
            else:
                logger.warning("May need to enter sudo password")
        except subprocess.TimeoutExpired:
            logger.warning("Sudo check timeout")

        logger.info("Preflight checks completed")
        return True
    
    def run(self, operation):
        """Main execution function"""
        logger.info(f"Starting traffic collection for {self.script_dir.name}")

        if not self.preflight_checks():
            logger.warning("Preflight checks failed - continuing anyway")

        try:
            if operation == 'normal':
                return self.collect_single('normal')
            elif operation == 'malicious':
                return self.collect_single('malicious')
            elif operation == 'both':
                logger.info("=== Starting sequential collection ===")

                if not self.collect_single('normal'):
                    logger.error("Normal collection failed")
                    return False

                logger.info("Waiting 10 seconds before malicious collection...")
                time.sleep(10)

                if not self.collect_single('malicious'):
                    logger.error("Malicious collection failed")
                    return False

                logger.info("=== All collections completed ===")
                return True
            else:
                logger.error(f"Unknown operation: {operation}")
                return False

        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            self.cleanup()
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self.cleanup()
            return False


def collect_traffic(cve_number, operation, port=8080, verbose=False):
    """
    External function interface for traffic collection

    Args:
        cve_number (str): CVE number (e.g., 'CVE-2021-26120')
        operation (str): Type of traffic to collect ('normal', 'malicious', or 'both')
        port (int): Port number for the target service (default: 8080)
        verbose (bool): Enable verbose output

    Returns:
        bool: True if successful, False otherwise
    """
    if operation not in ['normal', 'malicious', 'both']:
        raise ValueError("Operation must be 'normal', 'malicious', or 'both'")

    collector = TrafficCollector(cve_number, port)
    return collector.run(operation)
