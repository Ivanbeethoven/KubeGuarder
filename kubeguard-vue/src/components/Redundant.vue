<template>
  <el-container style="height: 100%; padding: 0;">
    <el-aside width="300px" style=" background-color: #B3C0D1">
      <div >
        <div style="margin-top: 20px"><span style="margin-left: 10px; font-weight: bold">审计日志上传</span></div>
        <el-upload
          drag
          class="upload-demo"
          ref="upload"
          action=""
          :on-preview="handlePreview"
          :on-remove="handleRemove"
          :on-change="handleChange"
          :file-list="fileList"
          :auto-upload="false"
          :show-file-list="true"
          accept=".txt, .log"
          :limit="50"
        >
          <i class="el-icon-upload"></i>
          <div class="el-upload__text">拖拽 或 <em>点击</em>上传审计日志文件</div>
        </el-upload>
        <el-divider></el-divider>

        <div style="margin-top: 10px; display: flex; align-items: center; justify-content: center;">
          <el-button size="medium" type="primary" @click="submitUpload" >执行检测</el-button>
        </div>

      </div>
    </el-aside>
    <el-main>
      <el-container v-show="!showEmpty">
        <el-aside width="260px" class="inner-aside">
          <div style="font-weight: bold; margin-bottom: 10px">检测结果统计</div>
          <el-descriptions  border column="1" size="mini" style="margin-bottom: 10px">
            <el-descriptions-item label="审计日志总数">{{report.eventNum}}</el-descriptions-item>
            <el-descriptions-item label="训练样本总数">{{ report.trainExampleNum }}</el-descriptions-item>
            <el-descriptions-item label="检测样本总数">{{report.testExampleNum}}</el-descriptions-item>
            <el-descriptions-item label="服务账户总数">{{ report.accountNum }}</el-descriptions-item>
            <el-descriptions-item label="检测出的冗余权限数量">{{ report.redundantNum }}</el-descriptions-item>
          </el-descriptions>
          <div class="menu-scroll-container">
            <div style="font-weight: bold; margin-bottom: 10px">服务账户列表</div>
            <el-menu :default-active="activeItem.account" @select="handleSelect">
              <!-- 菜单列表，动态生成列表项 -->
              <el-menu-item v-for="(item, index) in report.accountWithAuthList" :key="item.account" :index="index">
                {{ item.account }}
              </el-menu-item>
            </el-menu>
          </div>
        </el-aside>
        <el-main style="padding-top: 0">
          <div style="font-weight: bold; margin-bottom: 10px">服务账户权限列表</div>
          <div class="collapse-container">
            <el-collapse>
              <el-collapse-item v-for="(kindAuth, index) in activeItem.kindAuthList">
                <template slot="title">
                  <el-tag size="mini" type="warning" style="margin-left: 10px; margin-right: 10px;">{{ kindAuth.verb }}</el-tag>
                  <span style="margin-right: 10px; font-weight: bold;">{{ kindAuth.kind }}</span>
                  <el-tag v-if="kindAuth.redundant === true" size="mini" type="danger">Redundant</el-tag>
                </template>
                <div>
                  <el-table
                    empty-text="No data"
                    border
                    class="table-expand"
                    :data="kindAuth.resourceAuthList"
                    stripe
                    style="width: 100%">
                    <el-table-column align="center"
                      prop="name"
                      label="Resource Name"
                      width="250">
                    </el-table-column>
                    <el-table-column align="center"
                      label="Verb"
                      width="120">
                      <template slot-scope="scope">
                        <el-tag type="warning" size="mini" style="margin-left: 10px; margin-right: 10px;">{{ kindAuth.verb }}</el-tag>
                      </template>
                    </el-table-column>
                    <el-table-column align="center"
                      prop="predict"
                      label="Predictive Value"
                      width="120">
                    </el-table-column>
                  </el-table>
                </div>
                <el-divider></el-divider>
              </el-collapse-item>
            </el-collapse>
          </div>

        </el-main>
      </el-container>
     <el-empty v-show="showEmpty" description="Waiting detection results..."></el-empty>
    </el-main>
  </el-container>
</template>

<script>
import {url} from "../js/config";

export default {
  name: "Redundant",
  data(){
    return {
      report: {},
      showEmpty: true,
      activeItem: '',
      defaultActiveItem: ''
    }
  },
  created() {
    this.getResultList();
  },
  methods: {
    getResultList(){
      this.$http.get(url + "/redundant/results").then(res => {
        this.report = res.data
        this.activeItem = this.report.accountWithAuthList[0]
      })
    },

    handleSelect(index){
      this.activeItem = this.report.accountWithAuthList[index]
    },

    handlePreview(file) {
      console.log('fileList', this.fileList)
      console.log(file);
    },
    handleRemove(file, fileList) {
      console.log(file, fileList);
    },
    handleChange(file, fileList){
      console.log(file, fileList)
    },
    submitUpload() {
      this.showEmpty = !this.showEmpty
    },
  }
}
</script>

<style scoped>
>>>.el-upload-dragger {
  background-color: #fff;
  margin-top: 10px;
  margin-left: 20px;
  border: 1px dashed #d9d9d9;
  border-radius: 6px;
  -webkit-box-sizing: border-box;
  box-sizing: border-box;
  width: 260px;
  height: 150px;
  text-align: center;
  cursor: pointer;
  overflow: hidden;
}

.table-expand {
  font-size: 12px;
  margin-left: 3%;
  margin-bottom: 5px;
  width: 94%;
}

.inner-aside{
  display: flex;
  flex-direction: column;
  height: 100%;
}

.menu-scroll-container{
  flex-grow: 1; /* 允许菜单部分占据所有剩余空间 */
  overflow-y: auto; /* 内容超出时显示滚动条 */
}

.el-menu--vertical .el-menu-item {
  padding-top: 5px;
  padding-bottom: 5px;
}
.collapse-container {
  max-height: 430px; /* 根据实际需求调整 */
  overflow-y: auto;
}
</style>
