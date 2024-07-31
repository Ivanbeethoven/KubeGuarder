<template>
  <el-container style="height: 100%; padding: 0;">
    <el-aside width="60%" style=" background-color: #B3C0D1">
      <div class="left-title">
        <div>
          <el-button type="primary"
                     @click=" open = !open"
                     style="margin-left: 20px; margin-right: 10px">
            <i v-if="open" class="el-icon-video-pause"></i>
            <i v-else class="el-icon-video-play"></i>
          </el-button>
          <span v-if="open">集群资源操作监控已开启</span>
          <span v-else>集群资源操作监控已关闭</span>
        </div>
        <div>
          <el-input v-model="search" placeholder="请输入内容" style="width: 200px"></el-input>
          <el-button type="primary">查找</el-button>
        </div>
      </div>
      <div>
        <el-table
          :data="resultList"
          highlight-current-row
          @row-click="handleRowClick"
          style="width: 100%; font-size: 12px;"
          height="450px"
        >
          <el-table-column prop="packetId" label="Packet ID" width="150" align="center"></el-table-column>
          <el-table-column label="Protocol" width="80" align="center">
            <template slot-scope="scope">
              <el-tag size="mini" type="warning"  style="margin-left: 10px; margin-right: 10px">{{ scope.row.protocol }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Source" width="120" align="center">
            <template slot-scope="scope">
              <div>
                {{scope.row.srcIp}}
              </div>
              <div v-if="scope.row.srcAccount !== null">
                <el-tag size="mini">{{ scope.row.srcAccount }}</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="Destination" width="120" align="center">
            <template slot-scope="scope">
              <div>
                {{scope.row.dstIp}}
              </div>
              <div v-if="scope.row.dstAccount !== null">
                <el-tag size="mini">{{ scope.row.dstAccount }}</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="Node" width="120" align="center">
            <template slot-scope="scope">
              <div>
                {{scope.row.nodeIp}}
              </div>
              <div>
                <el-tag size="mini" type="info">{{ scope.row.nodeName }}</el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column label = "Details"
            align="center">
            <template slot-scope="scope">
              <el-button
                size="mini"
                @click="showPacket(scope.$index, scope.row)">数据包详情</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-aside>
    <el-main style="display: flex; flex-direction: column; height: 100%">
      <div style="margin-bottom: 5px">资源泄漏详情-Request:</div>
      <div class="json-details" style="margin-bottom: 10px">
        <pre><code>{{ formattedSelectedRequestData }}</code></pre>
      </div>
      <div style="margin-bottom: 5px">资源泄露详情-Response:</div>
      <div class="json-details">
        <pre><code>{{ formattedSelectedResponseData }}</code></pre>
      </div>
    </el-main>
  </el-container>
</template>

<script>
import {url} from "../js/config";

export default {
  name: "Sensitive",
  data(){
    return{
      open: false,
      selectedResult: '',
      rowIndex: '',
      resultList: [{
        packetId: '000000056192.pcap-0',
        protocol: 'HTTP',
        srcIp: '10.244.1.56',
        srcAccount: 'test-4/test-4-sa',
        dstIp: '10.244.1.57',
        dstAccount: 'test-5/test-5-sa',
        nodeIp: '192.168.117.51',
        nodeName: 'node-1',
        request:'',
        response: '',
        packet: '',
      },
        {
          packetId: '000000056192.pcap-0',
          protocol: 'HTTP',
          srcIp: '10.244.1.56',
          srcAccount: 'test-4/test-4-sa',
          dstIp: '10.244.1.57',
          dstAccount: 'test-5/test-5-sa',
          nodeIp: '192.168.117.51',
          nodeName: 'node-1',
          request:'',
          response: '',
          packet: '',
        }],
      search: '',
    }
  },
  created() {
    this.getResultList()
  },
  methods :{
    getResultList(){
      this.$http.get(url + "/sensitive/results").then(res => {
        this.resultList = res.data
      })
    },
    showPacket(index, row){

    },
    handleRowClick(row, rowIndex){
      this.selectedResult = row;
      this.rowIndex = rowIndex;
    },
  },
  computed:{
    formattedSelectedRequestData() {
      if (this.selectedResult.request) {
        return JSON.stringify(this.selectedResult.request, null, 2);
      }
      return '';
    },
    formattedSelectedResponseData() {
      if (this.selectedResult.response) {
        return JSON.stringify(this.selectedResult.response, null, 2);
      }
      return '';
    }
  }

}
</script>

<style scoped>
.left-title {
  padding: 10px;
  display: flex;
  align-items: center; /* 垂直居中 */
  justify-content: space-between; /* 确保内容从左侧开始 */
  border-bottom: 2px solid #FFFFFF;
}

.details-section h2 {
  margin-top: 0;
  color: #333; /* 标题颜色 */
}

.json-details {
  background-color: #FFFFFF;
  border: gray solid 2px;
  flex: 1;
  overflow: auto;
}

.json-details code {
  color: #2e6da4; /* JSON文本颜色 */
}
</style>
