#!/bin/bash
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

BMV2_PATH=$THIS_DIR/../../bmv2

P4C_BM_PATH=$THIS_DIR/../../p4c-bmv2


P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py

TARGET=simple_switch
TARGET_SRC=$TARGET.p4
TARGET_JSON=$TARGET.json

LOG_PATH=ss-log

$P4C_BM_SCRIPT p4src/$TARGET_SRC --json $TARGET_JSON
# This gives libtool the opportunity to "warm-up"
sudo $SWITCH_PATH >/dev/null 2>&1
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python topo.py \
    --behavioral-exe $SWITCH_PATH \
    --json $TARGET_JSON \
    --cli $CLI_PATH \
    --log-file $LOG_PATH
